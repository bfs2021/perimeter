package service_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/auditevent"
	"perimeter/ent/user"
	"perimeter/internal/service"
)

// writeUser makes a user with the role, for the actor of a write.
func (f *fixture) writeUser(email string, role user.Role) *ent.User {
	f.t.Helper()
	u, err := f.client.User.Create().
		SetEmail(email).
		SetName(email).
		SetRole(role).
		SetConfirmed(true).
		Save(f.ctx)
	f.must(err)
	return u
}

// writeToken makes an API token for u with the given prefix.
func (f *fixture) writeToken(u *ent.User, prefix string, scope apitoken.Scope) *ent.APIToken {
	f.t.Helper()
	tok, err := f.client.APIToken.Create().
		SetName("test").
		SetScope(scope).
		SetTokenHash(prefix + "-hash").
		SetPrefix(prefix).
		SetUser(u).
		Save(f.ctx)
	f.must(err)
	return tok
}

// audits returns every audit row, oldest first.
func (f *fixture) audits() []*ent.AuditEvent {
	f.t.Helper()
	rows, err := f.client.AuditEvent.Query().Order(ent.Asc(auditevent.FieldID)).All(f.ctx)
	f.must(err)
	return rows
}

// auditsFor returns the audit rows with the action, oldest first.
func (f *fixture) auditsFor(action string) []*ent.AuditEvent {
	f.t.Helper()
	var out []*ent.AuditEvent
	for _, r := range f.audits() {
		if r.Action == action {
			out = append(out, r)
		}
	}
	return out
}

// tagNames returns the sorted tag names of a summary.
func tagNames(s *service.TargetSummary) []string {
	out := slices.Clone(s.Tags)
	slices.Sort(out)
	return out
}

func TestImportTargetsReportsAndAudits(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)
	tok := f.writeToken(admin, "prm_ab12cd34", apitoken.ScopeWrite)
	f.target("existing.example.com")
	f.target("gone.example.com")
	goneID := f.id("gone.example.com")
	f.must(f.st.DeleteTarget(f.ctx, goneID))

	actor := service.Actor{User: admin, Source: service.SourceAPI, Token: tok}
	res, err := f.svc.ImportTargets(f.ctx, actor, []string{
		"new.example.com\nexisting.example.com",
		"gone.example.com",
		"not valid!",
	})
	f.must(err)

	if !slices.Equal(res.Added, []string{"new.example.com"}) {
		t.Errorf("Added = %v", res.Added)
	}
	if !slices.Equal(res.Existing, []string{"existing.example.com"}) {
		t.Errorf("Existing = %v", res.Existing)
	}
	if !slices.Equal(res.Restored, []string{"gone.example.com"}) {
		t.Errorf("Restored = %v", res.Restored)
	}
	if !slices.Equal(res.Invalid, []string{"not valid!"}) {
		t.Errorf("Invalid = %v", res.Invalid)
	}
	statuses := map[string]string{}
	for _, ref := range res.Targets {
		statuses[ref.Input] = ref.Status
		if ref.ID != f.id(ref.Input) {
			t.Errorf("ref %s has id %d", ref.Input, ref.ID)
		}
	}
	want := map[string]string{
		"new.example.com":      "added",
		"existing.example.com": "existing",
		"gone.example.com":     "restored",
	}
	if fmt.Sprint(statuses) != fmt.Sprint(want) {
		t.Errorf("target statuses = %v, want %v", statuses, want)
	}

	rows := f.auditsFor("target.import")
	if len(rows) != 1 {
		t.Fatalf("%d target.import rows, want 1", len(rows))
	}
	r := rows[0]
	if r.Source != auditevent.SourceAPI || r.ActorEmail != admin.Email || r.ActorID == nil || *r.ActorID != admin.ID {
		t.Errorf("row actor = %+v", r)
	}
	if r.TokenPrefix != "prm_ab12cd34" {
		t.Errorf("token prefix = %q", r.TokenPrefix)
	}
	if r.Detail != "1 added, 1 restored, 1 invalid" {
		t.Errorf("detail = %q", r.Detail)
	}
	if !strings.Contains(r.Object, "new.example.com") || !strings.Contains(r.Object, "gone.example.com") {
		t.Errorf("object = %q", r.Object)
	}
}

func TestImportTargetsNoAuditWhenNothingChanged(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)
	f.target("existing.example.com")
	actor := service.Actor{User: admin, Source: service.SourceAPI}

	res, err := f.svc.ImportTargets(f.ctx, actor, []string{"existing.example.com", "not valid!"})
	f.must(err)
	if !slices.Equal(res.Existing, []string{"existing.example.com"}) || !slices.Equal(res.Invalid, []string{"not valid!"}) {
		t.Errorf("result = %+v", res)
	}
	if n := len(f.audits()); n != 0 {
		t.Errorf("%d audit rows, want 0", n)
	}
}

func TestImportTargetsLimit(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)

	var lines []string
	for i := range 1001 {
		lines = append(lines, fmt.Sprintf("host%d.example.com", i))
	}
	_, err := f.svc.ImportTargets(f.ctx, service.Actor{User: admin, Source: service.SourceAPI}, lines)
	if !service.IsInvalid(err) {
		t.Fatalf("1001 lines: err = %v, want InvalidError", err)
	}
	if n := f.client.Target.Query().CountX(f.ctx); n != 0 {
		t.Errorf("%d targets imported after a refused call", n)
	}
	if n := len(f.audits()); n != 0 {
		t.Errorf("%d audit rows after a refused call", n)
	}
}

func TestSetAddRemoveTargetTags(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)
	f.target("tagged.example.com")
	id := f.id("tagged.example.com")
	f.client.Tag.Create().SetName("prod").SetColor("#111111").SaveX(f.ctx)
	f.client.Tag.Create().SetName("dmz").SetColor("#222222").SaveX(f.ctx)
	actor := service.Actor{User: admin, Source: service.SourceMCP}

	sum, err := f.svc.SetTargetTags(f.ctx, actor, id, []string{"prod"})
	f.must(err)
	if got := tagNames(sum); !slices.Equal(got, []string{"prod"}) {
		t.Fatalf("after set: tags %v", got)
	}

	// An unknown name refuses the whole call and names it.
	_, err = f.svc.SetTargetTags(f.ctx, actor, id, []string{"prod", "nope", "gone2"})
	var ie *service.InvalidError
	if !errors.As(err, &ie) || !strings.Contains(ie.Msg, "nope") || !strings.Contains(ie.Msg, "gone2") {
		t.Fatalf("unknown tags: err = %v, want InvalidError naming both", err)
	}
	if _, err := f.svc.AddTargetTags(f.ctx, actor, id, []string{"nope"}); !service.IsInvalid(err) {
		t.Errorf("add unknown: err = %v, want InvalidError", err)
	}
	if _, err := f.svc.RemoveTargetTags(f.ctx, actor, id, []string{"nope"}); !service.IsInvalid(err) {
		t.Errorf("remove unknown: err = %v, want InvalidError", err)
	}

	// Adding a tag the target already has does not duplicate it.
	sum, err = f.svc.AddTargetTags(f.ctx, actor, id, []string{"dmz", "prod"})
	f.must(err)
	if got := tagNames(sum); !slices.Equal(got, []string{"dmz", "prod"}) {
		t.Errorf("after add: tags %v", got)
	}

	sum, err = f.svc.RemoveTargetTags(f.ctx, actor, id, []string{"prod", "dmz"})
	f.must(err)
	if got := tagNames(sum); len(got) != 0 {
		t.Errorf("after remove: tags %v", got)
	}

	sum, err = f.svc.SetTargetTags(f.ctx, actor, id, nil)
	f.must(err)
	if len(sum.Tags) != 0 {
		t.Errorf("after clear: tags %v", sum.Tags)
	}

	rows := f.auditsFor("target.tags")
	if len(rows) != 4 {
		t.Fatalf("%d target.tags rows, want 4 (refused calls leave none)", len(rows))
	}
	if rows[0].Source != auditevent.SourceMcp || rows[0].Object != "tagged.example.com" {
		t.Errorf("first row = %+v", rows[0])
	}
	if rows[2].Detail != "tags removed dmz, prod" {
		t.Errorf("remove detail = %q", rows[2].Detail)
	}
}

func TestTargetTagWritesNotFound(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)
	f.target("gone.example.com")
	id := f.id("gone.example.com")
	f.must(f.st.DeleteTarget(f.ctx, id))
	actor := service.Actor{User: admin, Source: service.SourceAPI}

	if _, err := f.svc.SetTargetTags(f.ctx, actor, id, nil); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("tags on a deleted target: err = %v", err)
	}
	if _, err := f.svc.AddTargetTags(f.ctx, actor, 9999, nil); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("tags on a missing target: err = %v", err)
	}
}

func TestDeleteAndRestoreTarget(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)
	f.target("soft.example.com")
	id := f.id("soft.example.com")
	actor := service.Actor{User: admin, Source: service.SourceMCP}

	f.must(f.svc.DeleteTarget(f.ctx, actor, id))
	if got := f.list(service.TargetQuery{}); len(got) != 0 {
		t.Errorf("live list after delete = %v", got)
	}
	if err := f.svc.DeleteTarget(f.ctx, actor, id); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("delete twice: err = %v, want ErrNotFound", err)
	}
	if err := f.svc.DeleteTarget(f.ctx, actor, 9999); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("delete missing: err = %v, want ErrNotFound", err)
	}

	f.must(f.svc.RestoreTarget(f.ctx, actor, id))
	if got := f.list(service.TargetQuery{}); !slices.Equal(got, []string{"soft.example.com"}) {
		t.Errorf("live list after restore = %v", got)
	}
	if err := f.svc.RestoreTarget(f.ctx, actor, id); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("restore live: err = %v, want ErrNotFound", err)
	}

	del := f.auditsFor("target.delete")
	if len(del) != 1 || del[0].Object != "soft.example.com" || del[0].Source != auditevent.SourceMcp {
		t.Errorf("delete rows = %+v", del)
	}
	res := f.auditsFor("target.restore")
	if len(res) != 1 || res[0].ActorEmail != admin.Email {
		t.Errorf("restore rows = %+v", res)
	}
}

func TestRequestRescan(t *testing.T) {
	f := newFixture(t)
	admin := f.writeUser("admin@example.com", user.RoleAdmin)
	f.target("a.example.com")
	f.target("b.example.com")
	a, b := f.id("a.example.com"), f.id("b.example.com")
	f.svc.SetRescanConfig(time.Hour, false)
	actor := service.Actor{User: admin, Source: service.SourceAPI}

	res, err := f.svc.RequestRescan(f.ctx, actor, []int{a, b, 9999})
	f.must(err)
	if !slices.Equal(res.Queued, []int{a, b}) || !slices.Equal(res.NotFound, []int{9999}) || len(res.CoolingDown) != 0 {
		t.Fatalf("first rescan = %+v", res)
	}
	if ts := f.client.Target.GetX(f.ctx, a); ts.RescanRequestedAt == nil {
		t.Error("rescan was not stamped on the target")
	}

	// Asked again inside the cooldown, both are held back.
	res, err = f.svc.RequestRescan(f.ctx, actor, []int{a, b})
	f.must(err)
	if len(res.Queued) != 0 || len(res.CoolingDown) != 2 || res.CoolingDown[0].ID != a {
		t.Errorf("second rescan = %+v", res)
	}
	if res.CoolingDown[0].RetryAt.IsZero() {
		t.Error("cooling down without a retry time")
	}

	rows := f.auditsFor("target.rescan")
	if len(rows) != 2 {
		t.Fatalf("%d target.rescan rows, want 2", len(rows))
	}
	if rows[0].Object != "a.example.com, b.example.com" || rows[0].Detail != "2 queued, 0 cooling down, 1 not found" {
		t.Errorf("first rescan row = %+v", rows[0])
	}
}

func TestRequestRescanLimits(t *testing.T) {
	f := newFixture(t)
	actor := service.Actor{Source: service.SourceAPI}
	if _, err := f.svc.RequestRescan(f.ctx, actor, nil); !service.IsInvalid(err) {
		t.Errorf("no ids: err = %v, want InvalidError", err)
	}
	ids := make([]int, 501)
	for i := range ids {
		ids[i] = i + 1
	}
	if _, err := f.svc.RequestRescan(f.ctx, actor, ids); !service.IsInvalid(err) {
		t.Errorf("501 ids: err = %v, want InvalidError", err)
	}
}

func TestCanWrite(t *testing.T) {
	writeTok := &ent.APIToken{Scope: apitoken.ScopeWrite}
	readTok := &ent.APIToken{Scope: apitoken.ScopeRead}
	tests := []struct {
		name string
		u    *ent.User
		tok  *ent.APIToken
		want bool
	}{
		{"nil user", nil, nil, false},
		{"admin session", &ent.User{Role: user.RoleAdmin}, nil, true},
		{"member session", &ent.User{Role: user.RoleMember}, nil, true},
		{"viewer session", &ent.User{Role: user.RoleViewer}, nil, false},
		{"member write token", &ent.User{Role: user.RoleMember}, writeTok, true},
		{"admin read token", &ent.User{Role: user.RoleAdmin}, readTok, false},
		{"member read token", &ent.User{Role: user.RoleMember}, readTok, false},
		{"viewer write token", &ent.User{Role: user.RoleViewer}, writeTok, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := service.CanWrite(tt.u, tt.tok); got != tt.want {
				t.Errorf("CanWrite = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditRowsSurviveUserDeletion(t *testing.T) {
	f := newFixture(t)
	member := f.writeUser("member@example.com", user.RoleMember)
	f.target("kept.example.com")
	f.must(f.svc.DeleteTarget(f.ctx, service.Actor{User: member, Source: service.SourceUI}, f.id("kept.example.com")))

	f.must(f.client.User.DeleteOneID(member.ID).Exec(f.ctx))

	page, err := f.svc.ListAudit(f.ctx, 50, 0)
	f.must(err)
	if len(page.Items) != 1 {
		t.Fatalf("%d audit rows after user deletion, want 1", len(page.Items))
	}
	e := page.Items[0]
	if e.ActorEmail != "member@example.com" || e.ActorID == nil || *e.ActorID != member.ID {
		t.Errorf("row after deletion = %+v", e)
	}
	if e.Action != "target.delete" || e.Source != service.SourceUI {
		t.Errorf("row = %+v", e)
	}
}

func TestListAuditPages(t *testing.T) {
	f := newFixture(t)
	actor := service.Actor{Source: service.SourceUI}
	for _, action := range []string{"first", "second", "third"} {
		f.svc.Audit(f.ctx, actor, action, "obj", "")
	}

	page, err := f.svc.ListAudit(f.ctx, 2, 0)
	f.must(err)
	if page.Total != 3 || len(page.Items) != 2 || page.NextOffset == nil || *page.NextOffset != 2 {
		t.Fatalf("first page = %+v", page)
	}
	if page.Items[0].Action != "third" || page.Items[1].Action != "second" {
		t.Errorf("order = %s, %s; want newest first", page.Items[0].Action, page.Items[1].Action)
	}

	last, err := f.svc.ListAudit(f.ctx, 2, 2)
	f.must(err)
	if len(last.Items) != 1 || last.Items[0].Action != "first" || last.NextOffset != nil {
		t.Errorf("last page = %+v", last)
	}

	if _, err := f.svc.ListAudit(f.ctx, 2, -1); !service.IsInvalid(err) {
		t.Errorf("negative offset: err = %v, want InvalidError", err)
	}
}
