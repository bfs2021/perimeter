package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"perimeter/ent/user"
	"perimeter/internal/service"
)

// auditRows returns the audit rows with the action and object, newest first.
func auditRows(t *testing.T, srv *Server, action, object string) []service.AuditEntry {
	t.Helper()
	page, err := srv.svc.ListAudit(context.Background(), 200, 0)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	var out []service.AuditEntry
	for _, r := range page.Items {
		if r.Action == action && r.Object == object {
			out = append(out, r)
		}
	}
	return out
}

func TestImportWritesAuditRow(t *testing.T) {
	srv, _, token := authedServer(t)

	form := url.Values{"source": {"manual"}, "manual_input": {"audited.example.com"}}
	resp := postForm(t, srv, token, "/import", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /import: status %d; body:\n%s", resp.StatusCode, resp.Body)
	}

	rows := auditRows(t, srv, "target.import", "audited.example.com")
	if len(rows) != 1 {
		t.Fatalf("%d target.import rows, want 1", len(rows))
	}
	if rows[0].Source != service.SourceUI || rows[0].ActorEmail != "admin@test.com" {
		t.Errorf("row = %+v, want source ui by admin@test.com", rows[0])
	}
}

func TestUIWritesWriteAuditRows(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "audited.example.com")
	id := strconv.Itoa(ids["audited.example.com"])
	tagID := strconv.Itoa(client.Tag.Create().SetName("prod").SetColor("#111111").SaveX(context.Background()).ID)

	steps := []struct {
		name   string
		path   string
		form   url.Values
		action string
		object string
	}{
		{"delete", "/targets/" + id + "/delete", nil, "target.delete", "audited.example.com"},
		{"restore", "/targets/" + id + "/restore", nil, "target.restore", "audited.example.com"},
		{"tags", "/targets/" + id + "/tags", url.Values{"tags": {tagID}}, "target.tags", "audited.example.com"},
		{"tag create", "/tags", url.Values{"name": {"audited"}}, "tag.create", "audited"},
		{"invite", "/invite", url.Values{"email": {"new@example.com"}, "role": {"member"}}, "user.invite", "new@example.com"},
	}
	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			resp := postForm(t, srv, token, s.path, s.form)
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("POST %s: status %d; body:\n%s", s.path, resp.StatusCode, resp.Body)
			}
			rows := auditRows(t, srv, s.action, s.object)
			if len(rows) != 1 {
				t.Fatalf("%d %s rows for %s, want 1", len(rows), s.action, s.object)
			}
			if rows[0].Source != service.SourceUI || rows[0].ActorEmail != "admin@test.com" {
				t.Errorf("row = %+v, want source ui by admin@test.com", rows[0])
			}
		})
	}
}

func TestSettingsShowsAuditSection(t *testing.T) {
	srv, _, token := authedServer(t)
	resp := postForm(t, srv, token, "/import", url.Values{"source": {"manual"}, "manual_input": {"listed.example.com"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /import: status %d", resp.StatusCode)
	}

	reply, body := authedRequest(t, srv, token, "GET", "/settings")
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings: status %d", reply.StatusCode)
	}
	for _, want := range []string{"Audit log", "target.import", "listed.example.com", "admin@test.com", "/settings/audit"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page has no %q", want)
		}
	}
}

func TestAuditPagePaging(t *testing.T) {
	srv, _, token := authedServer(t)
	actor := service.Actor{Source: service.SourceAPI}
	for i := range 55 {
		srv.svc.Audit(context.Background(), actor, "bulk.test", fmt.Sprint(i), "")
	}

	reply, body := authedRequest(t, srv, token, "GET", "/settings/audit?page=2")
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings/audit?page=2: status %d", reply.StatusCode)
	}
	if !strings.Contains(body, "Page 2 of 2") {
		t.Errorf("page 2 is not the second of two pages")
	}

	// A page past the end shows the last one.
	_, body = authedRequest(t, srv, token, "GET", "/settings/audit?page=9")
	if !strings.Contains(body, "Page 2 of 2") {
		t.Errorf("page 9 did not clamp to the last page")
	}
}

func TestAuditPageIsAdminOnly(t *testing.T) {
	srv, _, tokens := roleServer(t)
	for _, role := range []user.Role{user.RoleViewer, user.RoleMember} {
		resp := send(t, srv, tokens[role], "GET", "/settings/audit", "", "")
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s GET /settings/audit: status %d, want 403", role, resp.StatusCode)
		}
	}
	resp := send(t, srv, tokens[user.RoleAdmin], "GET", "/settings/audit", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin GET /settings/audit: status %d, want 200", resp.StatusCode)
	}
}
