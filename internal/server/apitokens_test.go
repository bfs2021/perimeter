package server

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/user"
	"perimeter/internal/auth"
)

// rawTokenPattern matches a raw API token as the one-time page shows it.
var rawTokenPattern = regexp.MustCompile(`prm_[a-z2-7]{40}`)

// tokenCount returns how many API tokens exist in the database.
func tokenCount(t *testing.T, client *ent.Client) int {
	t.Helper()
	n, err := client.APIToken.Query().Count(t.Context())
	if err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	return n
}

// accountFlash opens the account page with the flash cookie a response set and
// returns the page body.
func accountFlash(t *testing.T, srv *Server, token string, resp response) string {
	t.Helper()
	page := requestWithCookies(t, srv, "GET", "/account", nil,
		&http.Cookie{Name: auth.SessionCookie, Value: token}, flashFrom(t, resp))
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /account: status %d, want 200", page.StatusCode)
	}
	return page.Body
}

// createTokenForm is the account form for a new token.
func createTokenForm(name, scope, expires string) url.Values {
	return url.Values{"name": {name}, "scope": {scope}, "expires": {expires}}
}

func TestAccountPageShowsAPITokensForEveryRole(t *testing.T) {
	srv, _, tokens := roleServer(t)
	for role, token := range tokens {
		resp := requestWithCookies(t, srv, "GET", "/account", nil,
			&http.Cookie{Name: auth.SessionCookie, Value: token})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: GET /account status %d, want 200", role, resp.StatusCode)
		}
		if !strings.Contains(resp.Body, "API tokens") || !strings.Contains(resp.Body, `action="/account/tokens"`) {
			t.Errorf("%s: account page has no API token section", role)
		}
		if strings.Contains(resp.Body, `id="token-code"`) {
			t.Errorf("%s: code field shown without two-factor", role)
		}
	}
}

func TestAPITokenCreateShowsTokenOnceAndStoresOnlyHash(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := tokens[user.RoleMember]

	resp := postForm(t, srv, member, "/account/tokens", createTokenForm("ci", "read", "90d"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: status %d, want 200; body %s", resp.StatusCode, resp.Body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q, want no-store", cc)
	}
	raw := rawTokenPattern.FindString(resp.Body)
	if raw == "" {
		t.Fatalf("created page does not show the token:\n%s", resp.Body)
	}

	// The token works, and the database holds only its hash.
	if me := apiCall(t, srv, "GET", "/api/v1/me", bearer(raw)); me.StatusCode != http.StatusOK {
		t.Errorf("new token: /api/v1/me status %d, want 200", me.StatusCode)
	}
	stored, err := client.APIToken.Query().Only(t.Context())
	if err != nil {
		t.Fatalf("stored token: %v", err)
	}
	if stored.TokenHash == raw || len(stored.TokenHash) != 64 {
		t.Errorf("stored token hash %q does not look like a SHA-256 hex digest of the token", stored.TokenHash)
	}
	if stored.ExpiresAt == nil || time.Until(*stored.ExpiresAt) < 89*24*time.Hour {
		t.Errorf("expiry %v, want about 90 days out", stored.ExpiresAt)
	}

	// Once shown, the raw token is not on any later page.
	account := requestWithCookies(t, srv, "GET", "/account", nil,
		&http.Cookie{Name: auth.SessionCookie, Value: member})
	if strings.Contains(account.Body, raw) {
		t.Error("raw token appears on the account page after creation")
	}
}

func TestAPITokenCreatePageShowsClientSnippets(t *testing.T) {
	srv, _, tokens := roleServer(t)
	resp := postForm(t, srv, tokens[user.RoleMember], "/account/tokens", createTokenForm("laptop", "read", "90d"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: status %d, want 200", resp.StatusCode)
	}
	raw := rawTokenPattern.FindString(resp.Body)
	if raw == "" {
		t.Fatal("created page does not show the token")
	}

	// html/template escapes the quotes in the snippets, so compare the text
	// after the snippets block. The base URL is the test request's host.
	page := html.UnescapeString(resp.Body)
	at := strings.Index(page, `id="token-snippets"`)
	if at < 0 {
		t.Fatal("created page has no token-snippets block")
	}
	snippets := page[at:]
	for _, want := range []string{
		`claude mcp add --transport http perimeter http://example.com/mcp --header "Authorization: Bearer ` + raw + `"`,
		`curl -H "Authorization: Bearer ` + raw + `" http://example.com/api/v1/summary`,
		`"args": ["-y", "mcp-remote", "http://example.com/mcp", "--header", "Authorization:${PERIMETER_AUTH}"]`,
		`"PERIMETER_AUTH": "Bearer ` + raw + `"`,
	} {
		if !strings.Contains(snippets, want) {
			t.Errorf("snippets do not contain %q", want)
		}
	}
}

func TestAPITokenCreateNeedsTwoFactorCode(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := tokens[user.RoleMember]
	secret, _ := enableTwoFactor(t, srv.auth, userByEmail(t, client, "member@test.com"))

	resp := postForm(t, srv, member, "/account/tokens", createTokenForm("ci", "read", "90d"))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("no code: status %d location %q, want 303 to /account", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n := tokenCount(t, client); n != 0 {
		t.Fatalf("token created without a code: %d tokens", n)
	}
	if body := accountFlash(t, srv, member, resp); !strings.Contains(body, "Invalid code.") {
		t.Error("account page does not show the invalid code error")
	}

	form := createTokenForm("ci", "read", "90d")
	form.Set("code", nextStepCode(t, secret))
	resp = postForm(t, srv, member, "/account/tokens", form)
	if resp.StatusCode != http.StatusOK || !rawTokenPattern.MatchString(resp.Body) {
		t.Fatalf("valid code: status %d, want 200 with a token", resp.StatusCode)
	}
	if n := tokenCount(t, client); n != 1 {
		t.Errorf("%d tokens after a valid code, want 1", n)
	}
}

func TestAPITokenViewerCannotCreateWriteToken(t *testing.T) {
	srv, client, tokens := roleServer(t)
	viewer := tokens[user.RoleViewer]

	resp := postForm(t, srv, viewer, "/account/tokens", createTokenForm("rw", "write", "never"))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("viewer write: status %d, want 303", resp.StatusCode)
	}
	if body := accountFlash(t, srv, viewer, resp); !strings.Contains(body, "Viewers can only create read-only tokens.") {
		t.Error("account page does not show the viewer scope error")
	}
	if n := tokenCount(t, client); n != 0 {
		t.Errorf("%d tokens created for a viewer write request, want 0", n)
	}

	resp = postForm(t, srv, viewer, "/account/tokens", createTokenForm("ro", "read", "never"))
	if resp.StatusCode != http.StatusOK || !rawTokenPattern.MatchString(resp.Body) {
		t.Errorf("viewer read: status %d, want 200 with a token", resp.StatusCode)
	}
}

func TestAPITokenRejectsUnknownScopeAndExpiry(t *testing.T) {
	srv, _, tokens := roleServer(t)
	member := tokens[user.RoleMember]
	if resp := postForm(t, srv, member, "/account/tokens", createTokenForm("x", "admin", "90d")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown scope: status %d, want 400", resp.StatusCode)
	}
	if resp := postForm(t, srv, member, "/account/tokens", createTokenForm("x", "read", "forever")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown expiry: status %d, want 400", resp.StatusCode)
	}
}

func TestOwnerRevokesOwnTokenAndOthersCannot(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := userByEmail(t, client, "member@test.com")
	raw, tok, err := srv.auth.CreateAPIToken(t.Context(), member, "mine", "read", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	path := "/account/tokens/" + strconv.Itoa(tok.ID) + "/revoke"

	// A viewer who is not the owner gets no change.
	resp := postForm(t, srv, tokens[user.RoleViewer], path, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("other user revoke: status %d location %q, want 303 to /account", resp.StatusCode, resp.Header.Get("Location"))
	}
	if body := accountFlash(t, srv, tokens[user.RoleViewer], resp); !strings.Contains(body, "Token not found, or you cannot revoke it.") {
		t.Error("account page does not show the refusal")
	}
	if stored := client.APIToken.GetX(t.Context(), tok.ID); stored.RevokedAt != nil {
		t.Fatal("another user revoked the token")
	}

	resp = postForm(t, srv, tokens[user.RoleMember], path, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("owner revoke: status %d, want 303", resp.StatusCode)
	}
	if stored := client.APIToken.GetX(t.Context(), tok.ID); stored.RevokedAt == nil {
		t.Fatal("owner revoke did not set revoked_at")
	}
	if me := apiCall(t, srv, "GET", "/api/v1/me", bearer(raw)); me.StatusCode != http.StatusUnauthorized {
		t.Errorf("revoked token: /api/v1/me status %d, want 401", me.StatusCode)
	}
}

func TestAdminRevokesAnyTokenFromSettings(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := userByEmail(t, client, "member@test.com")
	_, tok, err := srv.auth.CreateAPIToken(t.Context(), member, "ci", "read", nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	path := "/settings/tokens/" + strconv.Itoa(tok.ID) + "/revoke"

	// Only admins reach the settings revoke route.
	if resp := postForm(t, srv, tokens[user.RoleMember], path, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member settings revoke: status %d, want 403", resp.StatusCode)
	}
	if stored := client.APIToken.GetX(t.Context(), tok.ID); stored.RevokedAt != nil {
		t.Fatal("member revoked a token from settings")
	}

	resp := postForm(t, srv, tokens[user.RoleAdmin], path, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("admin revoke: status %d location %q, want 303 to /settings", resp.StatusCode, resp.Header.Get("Location"))
	}
	if stored := client.APIToken.GetX(t.Context(), tok.ID); stored.RevokedAt == nil {
		t.Fatal("admin revoke did not set revoked_at")
	}
	if body := settingsFlash(t, srv, tokens[user.RoleAdmin], resp); !strings.Contains(body, "Token revoked.") {
		t.Error("settings page does not show the revoke confirmation")
	}
}

// A form error must not spend the code: TOTP codes can't be replayed, so the
// same code still works once the name is fixed.
func TestAPITokenBadNameKeepsTwoFactorCode(t *testing.T) {
	srv, client, tokens := roleServer(t)
	member := tokens[user.RoleMember]
	secret, _ := enableTwoFactor(t, srv.auth, userByEmail(t, client, "member@test.com"))
	code := nextStepCode(t, secret)

	form := createTokenForm("  ", "read", "90d")
	form.Set("code", code)
	resp := postForm(t, srv, member, "/account/tokens", form)
	if body := accountFlash(t, srv, member, resp); !strings.Contains(body, "Give the token a name") {
		t.Fatal("blank name was not rejected with the name error")
	}

	form = createTokenForm("ci", "read", "90d")
	form.Set("code", code)
	resp = postForm(t, srv, member, "/account/tokens", form)
	if resp.StatusCode != http.StatusOK || !rawTokenPattern.MatchString(resp.Body) {
		t.Fatalf("same code after fixing the name: status %d, want 200 with a token", resp.StatusCode)
	}
}
