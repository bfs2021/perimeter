package server

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/invite"
	"perimeter/ent/user"
	"perimeter/internal/auth"
	"perimeter/internal/importer"
	"perimeter/internal/notifier"
	"perimeter/internal/storage"
)

// roleServer builds the real router over the real storage with one user per
// role and returns it with a session token per role.
func roleServer(t *testing.T) (*Server, *ent.Client, map[user.Role]string) {
	t.Helper()
	client := newTestClient(t)
	ctx := context.Background()
	a, err := auth.New(ctx, auth.Config{SessionMaxAge: time.Hour}, client)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	srv := New(storage.NewEntStorage(client), a, client, importer.NewRegistry(), notifier.NewRegistry(), os.DirFS("../.."), 30*24*time.Hour, 50)

	tokens := make(map[user.Role]string, 3)
	for _, role := range []user.Role{user.RoleAdmin, user.RoleMember, user.RoleViewer} {
		u, err := client.User.Create().
			SetEmail(string(role) + "@test.com").
			SetName(string(role)).
			SetRole(role).
			SetConfirmed(true).
			Save(ctx)
		if err != nil {
			t.Fatalf("create %s user: %v", role, err)
		}
		token, err := a.CreateSession(ctx, u)
		if err != nil {
			t.Fatalf("session for %s user: %v", role, err)
		}
		tokens[role] = token
	}
	return srv, client, tokens
}

// routeLevel is who may reach a route.
type routeLevel int

const (
	anyRole   routeLevel = iota // every authenticated user
	writeRole                   // admin and member
	adminRole                   // admin only
)

func TestRoleRoutePermissions(t *testing.T) {
	srv, client, tokens := roleServer(t)
	ids := importTargets(t, client, "perm.example.com")
	id := strconv.Itoa(ids["perm.example.com"])

	routes := []struct {
		name   string
		method string
		path   string
		level  routeLevel
	}{
		{"index", "GET", "/", anyRole},
		{"import page", "GET", "/import", writeRole},
		{"import submit", "POST", "/import", writeRole},
		{"bulk delete", "POST", "/targets/bulk/delete", writeRole},
		{"bulk export", "POST", "/targets/bulk/export", anyRole},
		{"bulk rescan", "POST", "/targets/bulk/rescan", writeRole},
		{"rescan target", "POST", "/targets/" + id + "/rescan", writeRole},
		{"delete target", "POST", "/targets/" + id + "/delete", writeRole},
		{"restore target", "POST", "/targets/" + id + "/restore", writeRole},
		{"purge target", "POST", "/targets/" + id + "/purge", adminRole},
		{"update tags", "POST", "/targets/" + id + "/tags", writeRole},
		{"settings", "GET", "/settings", adminRole},
		{"audit log", "GET", "/settings/audit", adminRole},
	}
	roles := []user.Role{user.RoleViewer, user.RoleMember, user.RoleAdmin}
	for _, role := range roles {
		for _, r := range routes {
			forbidden := (role == user.RoleViewer && r.level != anyRole) ||
				(role != user.RoleAdmin && r.level == adminRole)
			t.Run(string(role)+" "+r.name, func(t *testing.T) {
				resp := send(t, srv, tokens[role], r.method, r.path, "", "")
				if forbidden && resp.StatusCode != http.StatusForbidden {
					t.Fatalf("%s %s: status %d, want 403; body:\n%s", r.method, r.path, resp.StatusCode, resp.Body)
				}
				if !forbidden && resp.StatusCode == http.StatusForbidden {
					t.Fatalf("%s %s: status 403, want access; body:\n%s", r.method, r.path, resp.Body)
				}
			})
		}
	}
}

func TestUnknownPathForAuthenticatedNonAdminIs404(t *testing.T) {
	srv, _, tokens := roleServer(t)
	for _, role := range []user.Role{user.RoleMember, user.RoleViewer} {
		t.Run(string(role), func(t *testing.T) {
			resp := send(t, srv, tokens[role], "GET", "/no-such-page", "", "")
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET /no-such-page: status %d, want 404; body:\n%s", resp.StatusCode, resp.Body)
			}
			// Unknown URLs render the styled 404 page, not plain text.
			if !strings.Contains(resp.Body, "Page not found") || !strings.Contains(resp.Body, "Back to dashboard") {
				t.Errorf("GET /no-such-page body is not the error page; body:\n%s", resp.Body)
			}
		})
	}
}

func TestInviteWithViewerRole(t *testing.T) {
	srv, client, tokens := roleServer(t)

	form := url.Values{"email": {"viewer@example.com"}, "role": {"viewer"}}
	resp := postForm(t, srv, tokens[user.RoleAdmin], "/invite", form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("POST /invite: status %d, body:\n%s", resp.StatusCode, resp.Body)
	}

	inv, err := client.Invite.Query().
		Where(invite.EmailEQ("viewer@example.com")).
		Only(context.Background())
	if err != nil {
		t.Fatalf("look up invite: %v", err)
	}
	if inv.Role != invite.RoleViewer {
		t.Errorf("invite role %q, want viewer", inv.Role)
	}
}
