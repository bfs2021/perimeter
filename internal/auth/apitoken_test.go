package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/enttest"
	"perimeter/ent/user"
	"perimeter/internal/auth"
)

// newTestAuthClient is newTestAuth that also returns the ent client, for tests
// that set token timestamps directly.
func newTestAuthClient(t *testing.T) (*auth.Auth, *ent.Client) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	t.Cleanup(func() { client.Close() })

	a, err := auth.New(context.Background(), auth.Config{SessionMaxAge: 24 * time.Hour}, client)
	if err != nil {
		t.Fatalf("failed to create auth: %v", err)
	}
	return a, client
}

// registerUser adds a confirmed user with the role directly. Register would
// need an invite for every user after the first.
func registerUser(t *testing.T, client *ent.Client, email string, role user.Role) *ent.User {
	t.Helper()
	u, err := client.User.Create().
		SetEmail(email).
		SetName("Name").
		SetRole(role).
		SetConfirmed(true).
		Save(context.Background())
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return u
}

func TestAPITokenCreateValidateRevoke(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "admin@test.com", user.RoleAdmin)

	raw, tok, err := a.CreateAPIToken(ctx, u, "  ci  ", apitoken.ScopeWrite, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if !strings.HasPrefix(raw, "prm_") || len(raw) != len("prm_")+40 {
		t.Fatalf("raw token %q is not prm_ plus 40 characters", raw)
	}
	if raw != strings.ToLower(raw) {
		t.Errorf("raw token should be lowercase: %q", raw)
	}
	if tok.Prefix != raw[:12] {
		t.Errorf("prefix = %q, want %q", tok.Prefix, raw[:12])
	}
	if tok.Name != "ci" {
		t.Errorf("name = %q, want trimmed %q", tok.Name, "ci")
	}

	gotUser, gotTok, err := a.ValidateAPIToken(ctx, raw)
	if err != nil {
		t.Fatalf("ValidateAPIToken: %v", err)
	}
	if gotUser.ID != u.ID || gotTok.ID != tok.ID {
		t.Errorf("validate returned user %d token %d, want %d and %d", gotUser.ID, gotTok.ID, u.ID, tok.ID)
	}
	if gotTok.LastUsedAt == nil {
		t.Error("first use should set last_used_at")
	}

	if _, _, err := a.ValidateAPIToken(ctx, "prm_"+strings.Repeat("a", 40)); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("unknown token: got %v, want ErrTokenInvalid", err)
	}
	if _, _, err := a.ValidateAPIToken(ctx, "xyz_"+raw[4:]); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("wrong prefix: got %v, want ErrTokenInvalid", err)
	}

	if err := a.RevokeAPIToken(ctx, tok.ID, u); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if _, _, err := a.ValidateAPIToken(ctx, raw); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("revoked token: got %v, want ErrTokenInvalid", err)
	}
	// Revoking again is a no-op.
	if err := a.RevokeAPIToken(ctx, tok.ID, u); err != nil {
		t.Errorf("second revoke: %v", err)
	}
}

func TestAPITokenStoresOnlyHash(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "admin@test.com", user.RoleAdmin)

	raw, tok, err := a.CreateAPIToken(ctx, u, "ci", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	stored, err := client.APIToken.Get(ctx, tok.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.TokenHash == raw || strings.Contains(stored.TokenHash, raw) {
		t.Error("the raw token must not be stored")
	}
	if len(stored.TokenHash) != 64 {
		t.Errorf("token hash length %d, want 64 (sha-256 hex)", len(stored.TokenHash))
	}
}

func TestAPITokenExpired(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "admin@test.com", user.RoleAdmin)

	future := time.Now().Add(time.Hour)
	raw, tok, err := a.CreateAPIToken(ctx, u, "short", apitoken.ScopeRead, &future)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if _, _, err := a.ValidateAPIToken(ctx, raw); err != nil {
		t.Fatalf("token before expiry: %v", err)
	}

	if err := client.APIToken.UpdateOneID(tok.ID).SetExpiresAt(time.Now().Add(-time.Second)).Exec(ctx); err != nil {
		t.Fatalf("expire token: %v", err)
	}
	if _, _, err := a.ValidateAPIToken(ctx, raw); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("expired token: got %v, want ErrTokenInvalid", err)
	}
}

func TestAPITokenRejectsPastExpiry(t *testing.T) {
	a, client := newTestAuthClient(t)
	u := registerUser(t, client, "admin@test.com", user.RoleAdmin)
	past := time.Now().Add(-time.Hour)
	if _, _, err := a.CreateAPIToken(context.Background(), u, "old", apitoken.ScopeRead, &past); !errors.Is(err, auth.ErrTokenExpiry) {
		t.Errorf("past expiry: got %v, want ErrTokenExpiry", err)
	}
}

func TestAPITokenViewerCannotCreateWrite(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	viewer := registerUser(t, client, "viewer@test.com", user.RoleViewer)

	if _, _, err := a.CreateAPIToken(ctx, viewer, "rw", apitoken.ScopeWrite, nil); !errors.Is(err, auth.ErrTokenScope) {
		t.Fatalf("viewer write: got %v, want ErrTokenScope", err)
	}
	if _, _, err := a.CreateAPIToken(ctx, viewer, "ro", apitoken.ScopeRead, nil); err != nil {
		t.Errorf("viewer read: %v", err)
	}
}

func TestAPITokenNameRequired(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "admin@test.com", user.RoleAdmin)

	if _, _, err := a.CreateAPIToken(ctx, u, "   ", apitoken.ScopeRead, nil); !errors.Is(err, auth.ErrTokenName) {
		t.Errorf("blank name: got %v, want ErrTokenName", err)
	}
	if _, _, err := a.CreateAPIToken(ctx, u, strings.Repeat("n", 101), apitoken.ScopeRead, nil); !errors.Is(err, auth.ErrTokenName) {
		t.Errorf("101-character name: got %v, want ErrTokenName", err)
	}
}

func TestAPITokenLastUsedIsThrottled(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "admin@test.com", user.RoleAdmin)

	raw, tok, err := a.CreateAPIToken(ctx, u, "busy", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	// A value written 10 seconds ago is left alone.
	recent := time.Now().Add(-10 * time.Second)
	if err := client.APIToken.UpdateOneID(tok.ID).SetLastUsedAt(recent).Exec(ctx); err != nil {
		t.Fatalf("set last_used_at: %v", err)
	}
	if _, _, err := a.ValidateAPIToken(ctx, raw); err != nil {
		t.Fatalf("validate: %v", err)
	}
	stored, _ := client.APIToken.Get(ctx, tok.ID)
	if !stored.LastUsedAt.Equal(recent) {
		t.Errorf("last_used_at changed within a minute: %v, want %v", stored.LastUsedAt, recent)
	}

	// A value older than a minute is updated.
	old := time.Now().Add(-2 * time.Minute)
	if err := client.APIToken.UpdateOneID(tok.ID).SetLastUsedAt(old).Exec(ctx); err != nil {
		t.Fatalf("set last_used_at: %v", err)
	}
	if _, _, err := a.ValidateAPIToken(ctx, raw); err != nil {
		t.Fatalf("validate: %v", err)
	}
	stored, _ = client.APIToken.Get(ctx, tok.ID)
	if time.Since(*stored.LastUsedAt) > time.Minute {
		t.Errorf("last_used_at not refreshed after a minute: %v", stored.LastUsedAt)
	}
}

func TestAPITokenListAndRevokeRules(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	admin := registerUser(t, client, "admin@test.com", user.RoleAdmin)
	member := registerUser(t, client, "member@test.com", user.RoleMember)
	other := registerUser(t, client, "other@test.com", user.RoleMember)

	_, mine, err := a.CreateAPIToken(ctx, member, "mine", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	_, _, err = a.CreateAPIToken(ctx, member, "second", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	list, err := a.ListAPITokens(ctx, member.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListAPITokens: %d tokens, err %v; want 2", len(list), err)
	}
	if list[0].Name != "second" {
		t.Errorf("ListAPITokens order: first is %q, want newest (second)", list[0].Name)
	}
	if all, _ := a.ListAllAPITokens(ctx); len(all) != 2 || all[0].Edges.User == nil {
		t.Errorf("ListAllAPITokens: %d tokens, want 2 with users loaded", len(all))
	}

	if err := a.RevokeAPIToken(ctx, mine.ID, other); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("non-owner revoke: got %v, want ErrTokenInvalid", err)
	}
	if err := a.RevokeAPIToken(ctx, 9999, member); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("unknown id: got %v, want ErrTokenInvalid", err)
	}
	if err := a.RevokeAPIToken(ctx, mine.ID, admin); err != nil {
		t.Errorf("admin revoke: %v", err)
	}
}

func TestDeleteUserRemovesAPITokens(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "member@test.com", user.RoleMember)
	if _, _, err := a.CreateAPIToken(ctx, u, "ci", apitoken.ScopeRead, nil); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	if err := a.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if n, _ := client.APIToken.Query().Count(ctx); n != 0 {
		t.Errorf("%d API tokens remain after DeleteUser, want 0", n)
	}
}

func TestResetTOTPRevokesAPITokens(t *testing.T) {
	a, client := newTestAuthClient(t)
	ctx := context.Background()
	u := registerUser(t, client, "member@test.com", user.RoleMember)
	enableTOTP(t, a, u)

	raw, _, err := a.CreateAPIToken(ctx, u, "ci", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if err := a.ResetTOTP(ctx, u.ID); err != nil {
		t.Fatalf("ResetTOTP: %v", err)
	}

	if _, _, err := a.ValidateAPIToken(ctx, raw); !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("token after ResetTOTP: got %v, want ErrTokenInvalid", err)
	}
	stored, err := client.APIToken.Query().Only(ctx)
	if err != nil {
		t.Fatalf("token row should be kept: %v", err)
	}
	if stored.RevokedAt == nil {
		t.Error("revoked_at not set by ResetTOTP")
	}
}
