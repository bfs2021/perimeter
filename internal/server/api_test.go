package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"perimeter/ent/apitoken"
	"perimeter/ent/user"
	"perimeter/internal/auth"
)

// bearer returns the Authorization header for a raw API token.
func bearer(raw string) http.Header {
	return http.Header{"Authorization": {"Bearer " + raw}}
}

// apiCall sends one request through the real router. header and cookies are
// optional extras.
func apiCall(t *testing.T, srv *Server, method, path string, header http.Header, cookies ...*http.Cookie) response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range header {
		req.Header[k] = v
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(body)}
}

// apiErrorBodyCode returns the error code in a JSON error body, or "" if the body
// is not in that shape.
func apiErrorBodyCode(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body is not JSON: %v\n%s", err, body)
	}
	return out.Error.Code
}

func TestAPIRejectsMissingOrBadBearer(t *testing.T) {
	srv, _, _ := roleServer(t)
	cases := map[string]http.Header{
		"no header":    nil,
		"basic scheme": {"Authorization": {"Basic dXNlcjpwYXNz"}},
		"unknown":      bearer("prm_" + strings.Repeat("a", 40)),
		"no token":     {"Authorization": {"Bearer "}},
		"no prefix":    bearer(strings.Repeat("a", 44)),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			resp := apiCall(t, srv, "GET", "/api/v1/me", header)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401; body %s", resp.StatusCode, resp.Body)
			}
			if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("content type %q, want JSON", ct)
			}
			if code := apiErrorBodyCode(t, resp.Body); code != "unauthorized" {
				t.Errorf("error code %q, want unauthorized", code)
			}
		})
	}
}

func TestAPIMeWithValidToken(t *testing.T) {
	srv, client, _ := roleServer(t)
	for _, tc := range []struct {
		email, role string
	}{
		{"member@test.com", "member"},
		{"viewer@test.com", "viewer"},
	} {
		u := userByEmail(t, client, tc.email)
		raw, tok, err := srv.auth.CreateAPIToken(t.Context(), u, "cli", apitoken.ScopeRead, nil)
		if err != nil {
			t.Fatalf("CreateAPIToken: %v", err)
		}

		resp := apiCall(t, srv, "GET", "/api/v1/me", bearer(raw))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, want 200; body %s", tc.email, resp.StatusCode, resp.Body)
		}
		var me struct {
			Email string `json:"email"`
			Role  string `json:"role"`
			Token struct {
				Name   string `json:"name"`
				Scope  string `json:"scope"`
				Prefix string `json:"prefix"`
			} `json:"token"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &me); err != nil {
			t.Fatalf("decode /me: %v", err)
		}
		if me.Email != tc.email || me.Role != tc.role {
			t.Errorf("/me email %q role %q, want %q %q", me.Email, me.Role, tc.email, tc.role)
		}
		if me.Token.Name != "cli" || me.Token.Scope != "read" || me.Token.Prefix != tok.Prefix {
			t.Errorf("/me token %+v, want name cli, scope read, prefix %s", me.Token, tok.Prefix)
		}
		if strings.Contains(resp.Body, raw) {
			t.Error("/me must not echo the raw token")
		}
	}
}

func TestAPISessionCookieAloneIsNotAccepted(t *testing.T) {
	srv, _, tokens := roleServer(t)
	resp := apiCall(t, srv, "GET", "/api/v1/me", nil,
		&http.Cookie{Name: auth.SessionCookie, Value: tokens[user.RoleAdmin]})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cookie-only status %d, want 401", resp.StatusCode)
	}
	if code := apiErrorBodyCode(t, resp.Body); code != "unauthorized" {
		t.Errorf("error code %q, want unauthorized", code)
	}
}

func TestAPIRevokedTokenIsRejected(t *testing.T) {
	srv, client, _ := roleServer(t)
	u := userByEmail(t, client, "member@test.com")
	raw, tok, err := srv.auth.CreateAPIToken(t.Context(), u, "gone", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if err := srv.auth.RevokeAPIToken(t.Context(), tok.ID, u); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if resp := apiCall(t, srv, "GET", "/api/v1/me", bearer(raw)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked token status %d, want 401", resp.StatusCode)
	}
}

func TestAPIBearerIsNotBlockedByCrossOriginCheck(t *testing.T) {
	srv, client, tokens := roleServer(t)
	u := userByEmail(t, client, "member@test.com")
	raw, _, err := srv.auth.CreateAPIToken(t.Context(), u, "cli", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	evil := http.Header{"Origin": {"https://evil.example"}}
	header := bearer(raw)
	header.Set("Origin", "https://evil.example")
	if resp := apiCall(t, srv, "GET", "/api/v1/me", header); resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer call from a cross-site origin: status %d, want 200", resp.StatusCode)
	}

	// The same cross-site origin with a session cookie is still refused.
	resp := apiCall(t, srv, "POST", "/import", evil,
		&http.Cookie{Name: auth.SessionCookie, Value: tokens[user.RoleAdmin]})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie POST from a cross-site origin: status %d, want 403", resp.StatusCode)
	}
}

func TestAPIRateLimitReturns429WithRetryAfter(t *testing.T) {
	srv, client, _ := roleServer(t)
	srv.SetAPIRateLimit(2)
	u := userByEmail(t, client, "member@test.com")
	raw, _, err := srv.auth.CreateAPIToken(t.Context(), u, "busy", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	for i := 1; i <= 2; i++ {
		if resp := apiCall(t, srv, "GET", "/api/v1/me", bearer(raw)); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, resp.StatusCode)
		}
	}
	resp := apiCall(t, srv, "GET", "/api/v1/me", bearer(raw))
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third request: status %d, want 429", resp.StatusCode)
	}
	if ra := resp.Header.Get("Retry-After"); ra == "" {
		t.Error("429 without a Retry-After header")
	} else if _, err := strconv.Atoi(ra); err != nil {
		t.Errorf("Retry-After %q is not a number of seconds", ra)
	}
	if code := apiErrorBodyCode(t, resp.Body); code != "rate_limited" {
		t.Errorf("error code %q, want rate_limited", code)
	}
}

func TestAPIUnknownPathIsJSON404(t *testing.T) {
	srv, client, _ := roleServer(t)
	u := userByEmail(t, client, "member@test.com")
	raw, _, err := srv.auth.CreateAPIToken(t.Context(), u, "cli", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	resp := apiCall(t, srv, "GET", "/api/v1/x", bearer(raw))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d, want 404", resp.StatusCode)
	}
	if code := apiErrorBodyCode(t, resp.Body); code != "not_found" {
		t.Errorf("error code %q, want not_found", code)
	}
}
