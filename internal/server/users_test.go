package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/schema"
	"perimeter/ent/target"
	"perimeter/ent/user"
	"perimeter/internal/storage"
)

func TestDeleteUser(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()

	// A second user with a session, an invite and two owned targets, one of
	// them soft-deleted.
	u, err := client.User.Create().
		SetEmail("member@test.com").
		SetName("Member").
		SetRole(user.RoleMember).
		Save(ctx)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	_, err = client.Session.Create().
		SetTokenHash("member-session").
		SetExpiresAt(time.Now().Add(time.Hour)).
		SetUser(u).
		Save(ctx)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	_, err = client.Invite.Create().
		SetEmail("invitee@test.com").
		SetTokenHash("member-invite").
		SetExpiresAt(time.Now().Add(72 * time.Hour)).
		SetInvitedBy(u).
		Save(ctx)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	ids := importTargets(t, client, "own.live.example", "own.dead.example")
	if _, err := client.Target.Update().
		Where(target.IDIn(ids["own.live.example"], ids["own.dead.example"])).
		SetOwner(u).
		Save(ctx); err != nil {
		t.Fatalf("set target owner: %v", err)
	}
	if err := storage.NewEntStorage(client).DeleteTarget(ctx, ids["own.dead.example"]); err != nil {
		t.Fatalf("soft-delete target: %v", err)
	}

	// The settings page shows a delete form for the member but not for the
	// admin's own row.
	adminID, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).OnlyID(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}
	resp, body := authedRequest(t, srv, token, "GET", "/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings: status %d", resp.StatusCode)
	}
	if !strings.Contains(body, `action="/users/`+strconv.Itoa(u.ID)+`/delete"`) {
		t.Errorf("settings page missing delete form for the member")
	}
	if strings.Contains(body, `action="/users/`+strconv.Itoa(adminID)+`/delete"`) {
		t.Errorf("settings page shows a delete form for the admin's own row")
	}

	resp, _ = authedRequest(t, srv, token, "POST", "/users/"+strconv.Itoa(u.ID)+"/delete")
	if resp.StatusCode != http.StatusSeeOther || resp.Location != "/settings" {
		t.Fatalf("delete user: status %d location %q, want 303 to /settings", resp.StatusCode, resp.Location)
	}

	if _, err := client.User.Get(ctx, u.ID); !ent.IsNotFound(err) {
		t.Errorf("user still exists after delete (err %v)", err)
	}
	if n, err := client.Session.Query().Count(ctx); err != nil || n != 1 {
		t.Errorf("sessions after delete: %d (%v), want 1 (the admin's)", n, err)
	}
	if n, err := client.Invite.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("invites after delete: %d (%v), want 0", n, err)
	}
	for _, in := range []string{"own.live.example", "own.dead.example"} {
		tg, err := client.Target.Query().
			Where(target.InputEQ(in)).
			WithOwner().
			Only(schema.SkipSoftDelete(ctx))
		if err != nil {
			t.Fatalf("target %s: %v", in, err)
		}
		if tg.Edges.Owner != nil {
			t.Errorf("target %s still owned by the deleted user", in)
		}
	}

	if resp, _ := authedRequest(t, srv, token, "POST", "/users/99999/delete"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete unknown user: status %d, want 404", resp.StatusCode)
	}
}
