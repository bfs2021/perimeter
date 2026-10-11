package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"perimeter/internal/auth"
)

const wantCSP = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"

// requireSecurityHeaders checks the four hardening headers of issue #47 on
// a response.
func requireSecurityHeaders(t *testing.T, h http.Header) {
	t.Helper()
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := h.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want same-origin", got)
	}
	if got := h.Get("Content-Security-Policy"); got != wantCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", got, wantCSP)
	}
}

// headerGet runs a GET through the real router and returns its headers.
func headerGet(t *testing.T, srv *Server, token, path string) http.Header {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	}
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.Header
}

func TestSecurityHeadersLoginPage(t *testing.T) {
	srv, _, _ := authedServer(t)
	requireSecurityHeaders(t, headerGet(t, srv, "", "/login"))
}

func TestSecurityHeadersIndex(t *testing.T) {
	srv, _, token := authedServer(t)
	requireSecurityHeaders(t, headerGet(t, srv, token, "/"))
}

func TestSecurityHeadersNotFound(t *testing.T) {
	srv, _, token := authedServer(t)
	req := httptest.NewRequest("GET", "/no/such/page", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("GET /no/such/page: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	requireSecurityHeaders(t, resp.Header)
}
