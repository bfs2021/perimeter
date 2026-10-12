package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/auth"
	"perimeter/internal/importer"
	"perimeter/internal/notifier"
	"perimeter/internal/storage"
)

const fakeIdPClientID = "perimeter-test"

// fakeIdP is a minimal OpenID provider: discovery, a JWKS with one RSA key,
// and a token endpoint that answers any code with an ID token for email.
type fakeIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	email string
}

func newFakeIdP(t *testing.T, email string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	idp := &fakeIdP{key: key, email: email}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/auth",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
			"n": b64(key.N.Bytes()),
			"e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idp.idToken(t),
		})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// idToken signs an RS256 ID token for the provider's email.
func (idp *fakeIdP) idToken(t *testing.T) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss":   idp.srv.URL,
		"sub":   "user-1",
		"aud":   fakeIdPClientID,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"email": idp.email,
		"name":  "SSO User",
	})
	signed := b64(header) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// oidcServer builds the real router with OIDC pointed at idp. It registers a
// password admin first, so the provider's email resolves to that account.
func oidcServer(t *testing.T, idp *fakeIdP) (*Server, *ent.Client, *ent.User) {
	t.Helper()
	client := newTestClient(t)
	ctx := context.Background()
	a, err := auth.New(ctx, auth.Config{
		SessionMaxAge:    time.Hour,
		OIDCIssuer:       idp.srv.URL,
		OIDCClientID:     fakeIdPClientID,
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "http://example.com/auth/callback",
	}, client)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	srv := New(storage.NewEntStorage(client), a, client, importer.NewRegistry(), notifier.NewRegistry(), os.DirFS("../.."), 30*24*time.Hour, 50)
	return srv, client, u
}

// oidcCallback runs the provider redirect back to us with a matching state.
func oidcCallback(t *testing.T, srv *Server) response {
	t.Helper()
	return requestWithCookies(t, srv, "GET", "/auth/callback?state=s1&code=c1", nil,
		&http.Cookie{Name: "oidc_state", Value: "s1"})
}

func TestOIDCLoginWithoutTwoFactorGetsSession(t *testing.T) {
	idp := newFakeIdP(t, "admin@test.com")
	srv, _, _ := oidcServer(t, idp)

	resp := oidcCallback(t, srv)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: status %d location %q, want 302 to /; body:\n%s", resp.StatusCode, resp.Header.Get("Location"), resp.Body)
	}
	if cookieValue(resp, auth.SessionCookie) == "" {
		t.Error("callback did not set a session cookie")
	}
}

// An OIDC login resolves to an existing password account by email, so a user
// with two-factor on must not skip it by signing in through the provider.
func TestOIDCLoginWithTwoFactorNeedsSecondStep(t *testing.T) {
	idp := newFakeIdP(t, "admin@test.com")
	srv, client, admin := oidcServer(t, idp)
	ctx := context.Background()
	secret, _ := enableTwoFactor(t, srv.auth, admin)

	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := client.User.UpdateOne(admin).SetLastLoginAt(old).Save(ctx); err != nil {
		t.Fatalf("set last login: %v", err)
	}

	resp := oidcCallback(t, srv)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/2fa" {
		t.Fatalf("callback: status %d location %q, want 303 to /login/2fa; body:\n%s", resp.StatusCode, resp.Header.Get("Location"), resp.Body)
	}
	if cookieValue(resp, auth.SessionCookie) != "" {
		t.Fatal("callback set a session cookie before the second factor")
	}
	if got, _ := client.User.Get(ctx, admin.ID); got.LastLoginAt == nil || !got.LastLoginAt.Equal(old) {
		t.Errorf("last_login_at changed before the second factor: %v", got.LastLoginAt)
	}
	challenge := challengeCookie(t, resp)

	resp = requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {nextStepCode(t, secret)}}, challenge)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("correct code: status %d location %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if cookieValue(resp, auth.SessionCookie) == "" {
		t.Error("correct code did not set a session cookie")
	}
	if got, _ := client.User.Get(ctx, admin.ID); got.LastLoginAt == nil || got.LastLoginAt.Year() == 2000 {
		t.Errorf("last_login_at not updated after the second factor: %v", got.LastLoginAt)
	}
}
