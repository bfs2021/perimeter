package server

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"perimeter/ent"
	"perimeter/ent/user"
	"perimeter/internal/auth"
)

// userByEmail loads a user from the test database.
func userByEmail(t *testing.T, client *ent.Client, email string) *ent.User {
	t.Helper()
	u, err := client.User.Query().Where(user.EmailEQ(email)).Only(context.Background())
	if err != nil {
		t.Fatalf("look up %s: %v", email, err)
	}
	return u
}

// changeRole posts a role change for the user as the given session token.
func changeRole(t *testing.T, srv *Server, token string, id int, role string) response {
	t.Helper()
	return postForm(t, srv, token, "/users/"+strconv.Itoa(id)+"/role", url.Values{"role": {role}})
}

// settingsFlash opens the settings page with the flash cookie a response set
// and returns the page body.
func settingsFlash(t *testing.T, srv *Server, adminToken string, resp response) string {
	t.Helper()
	page := requestWithCookies(t, srv, "GET", "/settings", nil,
		&http.Cookie{Name: auth.SessionCookie, Value: adminToken}, flashFrom(t, resp))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings: status %d, want 200", page.StatusCode)
	}
	return page.Body
}

func TestAdminChangesViewerToMemberTakesEffectWithoutSignOut(t *testing.T) {
	srv, client, tokens := roleServer(t)
	viewer := userByEmail(t, client, "viewer@test.com")

	if resp := send(t, srv, tokens[user.RoleViewer], "GET", "/import", "", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer GET /import before change: status %d, want 403", resp.StatusCode)
	}

	resp := changeRole(t, srv, tokens[user.RoleAdmin], viewer.ID, "member")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("change role: status %d location %q, want 303 to /settings", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got := userByEmail(t, client, "viewer@test.com"); got.Role != user.RoleMember {
		t.Fatalf("stored role %q, want member", got.Role)
	}
	if body := settingsFlash(t, srv, tokens[user.RoleAdmin], resp); !strings.Contains(body, "viewer@test.com is now a member.") {
		t.Errorf("settings after change does not show the success flash")
	}

	// The viewer's existing session is not signed out and now reaches write routes.
	if resp := send(t, srv, tokens[user.RoleViewer], "GET", "/import", "", ""); resp.StatusCode == http.StatusForbidden {
		t.Errorf("viewer GET /import after promotion: status 403, want access")
	}
}

func TestAdminChangesMemberToViewerRemovesWriteAccess(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := userByEmail(t, client, "member@test.com")

	if resp := send(t, srv, tokens[user.RoleMember], "POST", "/import", "", ""); resp.StatusCode == http.StatusForbidden {
		t.Fatal("member POST /import before change: status 403, want access")
	}

	resp := changeRole(t, srv, tokens[user.RoleAdmin], member.ID, "viewer")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("change role: status %d, want 303", resp.StatusCode)
	}
	if got := userByEmail(t, client, "member@test.com"); got.Role != user.RoleViewer {
		t.Fatalf("stored role %q, want viewer", got.Role)
	}
	if body := settingsFlash(t, srv, tokens[user.RoleAdmin], resp); !strings.Contains(body, "member@test.com is now a viewer.") {
		t.Errorf("settings after change does not show the success flash")
	}

	if resp := send(t, srv, tokens[user.RoleMember], "POST", "/import", "", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("member POST /import after demotion: status %d, want 403", resp.StatusCode)
	}
}

func TestAdminPromotesMemberToAdmin(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := userByEmail(t, client, "member@test.com")

	resp := changeRole(t, srv, tokens[user.RoleAdmin], member.ID, "admin")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("promote: status %d, want 303", resp.StatusCode)
	}
	if got := userByEmail(t, client, "member@test.com"); got.Role != user.RoleAdmin {
		t.Fatalf("stored role %q, want admin", got.Role)
	}
	if body := settingsFlash(t, srv, tokens[user.RoleAdmin], resp); !strings.Contains(body, "member@test.com is now an admin.") {
		t.Errorf("settings after promotion does not show the success flash")
	}
}

func TestAdminRoleCannotBeChanged(t *testing.T) {
	srv, client, tokens := roleServer(t)
	ctx := context.Background()
	other, err := client.User.Create().
		SetEmail("other-admin@test.com").
		SetName("other admin").
		SetRole(user.RoleAdmin).
		SetConfirmed(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create second admin: %v", err)
	}

	resp := changeRole(t, srv, tokens[user.RoleAdmin], other.ID, "member")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("demote admin: status %d, want 403", resp.StatusCode)
	}
	if got, _ := client.User.Get(ctx, other.ID); got.Role != user.RoleAdmin {
		t.Errorf("admin role changed to %q", got.Role)
	}
}

func TestAdminCannotChangeOwnRole(t *testing.T) {
	srv, client, tokens := roleServer(t)
	admin := userByEmail(t, client, "admin@test.com")

	resp := changeRole(t, srv, tokens[user.RoleAdmin], admin.ID, "viewer")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("self change: status %d location %q, want 303 to /settings", resp.StatusCode, resp.Header.Get("Location"))
	}
	if body := settingsFlash(t, srv, tokens[user.RoleAdmin], resp); !strings.Contains(body, "Cannot change your own role.") {
		t.Errorf("settings after self change does not show the error flash")
	}
	if got := userByEmail(t, client, "admin@test.com"); got.Role != user.RoleAdmin {
		t.Errorf("own role changed to %q", got.Role)
	}
}

func TestNonAdminsCannotChangeRoles(t *testing.T) {
	srv, client, tokens := roleServer(t)
	viewer := userByEmail(t, client, "viewer@test.com")

	for _, role := range []user.Role{user.RoleMember, user.RoleViewer} {
		if resp := changeRole(t, srv, tokens[role], viewer.ID, "admin"); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s change role: status %d, want 403", role, resp.StatusCode)
		}
	}
	if got := userByEmail(t, client, "viewer@test.com"); got.Role != user.RoleViewer {
		t.Errorf("non-admin changed role to %q", got.Role)
	}
}

func TestChangeRoleRejectsBadInput(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := userByEmail(t, client, "member@test.com")

	if resp := changeRole(t, srv, tokens[user.RoleAdmin], member.ID, "owner"); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown role: status %d, want 400", resp.StatusCode)
	}
	if resp := send(t, srv, tokens[user.RoleAdmin], "POST", "/users/abc/role", "", ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-numeric id: status %d, want 400", resp.StatusCode)
	}
	if resp := changeRole(t, srv, tokens[user.RoleAdmin], 99999, "viewer"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown user: status %d, want 404", resp.StatusCode)
	}
	if got := userByEmail(t, client, "member@test.com"); got.Role != user.RoleMember {
		t.Errorf("role changed to %q after rejected requests", got.Role)
	}
}

func TestSettingsRoleCellShowsFormOnlyForNonAdmins(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := userByEmail(t, client, "member@test.com")
	admin := userByEmail(t, client, "admin@test.com")

	resp := send(t, srv, tokens[user.RoleAdmin], "GET", "/settings", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings: status %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, `action="/users/`+strconv.Itoa(member.ID)+`/role"`) {
		t.Errorf("settings has no role form for the member")
	}
	if strings.Contains(resp.Body, `action="/users/`+strconv.Itoa(admin.ID)+`/role"`) {
		t.Errorf("settings shows a role form for the admin's own row")
	}
}
