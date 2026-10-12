package auth_test

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"perimeter/ent/apitoken"
	"perimeter/ent/user"
	"perimeter/internal/auth"

	"github.com/gofiber/fiber/v2"
)

func TestRequireAPIWriteChecksScopeAndRole(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	member := registerUser(t, client, "member@test.com", user.RoleMember)
	viewer := registerUser(t, client, "viewer@test.com", user.RoleViewer)

	app := fiber.New()
	app.Get("/w", auth.RequireAPIToken(a), auth.RequireAPIWrite(), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})
	get := func(header string) (int, string) {
		t.Helper()
		req := httptest.NewRequest("GET", "/w", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("GET /w: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	writeRaw, _, err := a.CreateAPIToken(ctx, member, "rw", apitoken.ScopeWrite, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	readRaw, _, err := a.CreateAPIToken(ctx, member, "ro", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	viewerRaw, _, err := a.CreateAPIToken(ctx, viewer, "viewer", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	if code, body := get("Bearer " + writeRaw); code != 200 || body != "ok" {
		t.Errorf("member write token: status %d body %q, want 200", code, body)
	}
	if code, body := get("Bearer " + readRaw); code != 403 || !strings.Contains(body, "this token is read-only") {
		t.Errorf("member read token: status %d body %s, want 403 read-only", code, body)
	}
	if code, body := get("Bearer " + viewerRaw); code != 403 || !strings.Contains(body, "this token is read-only") {
		t.Errorf("viewer read token: status %d body %s, want 403 read-only", code, body)
	}
	if code, _ := get(""); code != 401 {
		t.Errorf("no header: status %d, want 401", code)
	}

	// The role is read per request, so a demoted member loses write at once.
	if _, err := client.User.UpdateOne(member).SetRole(user.RoleViewer).Save(ctx); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if code, body := get("Bearer " + writeRaw); code != 403 || !strings.Contains(body, "your role cannot change data") {
		t.Errorf("demoted member write token: status %d body %s, want 403 role", code, body)
	}
}
