package server

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"perimeter/internal/auth"
	"perimeter/internal/notifier"
)

// run sends req through the real router and reads the reply. The body is read
// and closed inside run.
func run(t *testing.T, srv *Server, req *http.Request) response {
	t.Helper()
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b)}
}

// flashSetCookie returns the flash cookie a reply sets, or nil if it sets none.
func flashSetCookie(t *testing.T, r response) *http.Cookie {
	t.Helper()
	for _, line := range r.Header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			t.Fatalf("parse Set-Cookie %q: %v", line, err)
		}
		if c.Name == flashCookie {
			return c
		}
	}
	return nil
}

// cookieCleared reports whether a Set-Cookie expires c at once: no value, and
// either Max-Age zero or an expiry in the past.
func cookieCleared(c *http.Cookie) bool {
	if c == nil || c.Value != "" {
		return false
	}
	return c.MaxAge < 0 || (c.MaxAge == 0 && !c.Expires.IsZero() && c.Expires.Before(time.Now()))
}

// followRedirect does what a browser does with a 303: it GETs the Location,
// sending back the flash cookie the redirect set. It returns the page the
// browser lands on.
func followRedirect(t *testing.T, srv *Server, token string, redirect response) response {
	t.Helper()
	if redirect.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d, want 303; body:\n%s", redirect.StatusCode, redirect.Body)
	}
	req := httptest.NewRequest(http.MethodGet, redirect.Header.Get("Location"), nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
	if c := flashSetCookie(t, redirect); c != nil && c.Value != "" {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return run(t, srv, req)
}

func TestRejectedEmailNotifierRedirectsAndPrefills(t *testing.T) {
	srv, client, token := notifierServer(t)
	// The real email factory with no sender is what a server without SMTP_HOST runs.
	reg := notifier.NewRegistry()
	reg.Register("email", notifier.NewEmailFactory(nil))
	srv.notifierRegistry = reg

	redirect := postForm(t, srv, token, "/notifiers", createNotifierForm(
		"email",
		`{"to":["oncall@example.com","alerts@example.com"]}`,
		string(notifier.EventSSLGradeDrop),
	))
	page := followRedirect(t, srv, token, redirect)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200; body:\n%s", page.StatusCode, page.Body)
	}

	for _, want := range []string{
		`role="alert"`,
		"Invalid notifier config",
		"need an SMTP server",
		`<option value="email" selected>`,
		"oncall@example.com\nalerts@example.com",
		`value="` + string(notifier.EventSSLGradeDrop) + `" checked`,
		`value="` + string(notifier.EventCSPIssues) + `" >`,
	} {
		if !strings.Contains(page.Body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
	if n, _ := client.NotifierConfig.Query().Count(context.Background()); n != 0 {
		t.Errorf("%d notifiers stored after rejected input, want 0", n)
	}
}

func TestFlashIsShownOnceAfterRedirect(t *testing.T) {
	srv, _, token := authedServer(t)

	redirect := postForm(t, srv, token, "/tags", url.Values{"name": {"prod"}, "color": {"#112233"}})
	page := followRedirect(t, srv, token, redirect)
	if !strings.Contains(page.Body, `role="status"`) || !strings.Contains(page.Body, `&#34;prod&#34; created.`) {
		t.Fatalf("created message missing after redirect; body:\n%s", page.Body)
	}
	// The page that shows the flash clears the cookie.
	if c := flashSetCookie(t, page); !cookieCleared(c) {
		t.Errorf("flash cookie not cleared on the page that showed it: %+v", c)
	}

	// A reload arrives without the cookie and must not show the message again.
	again := send(t, srv, token, "GET", "/settings", "", "")
	if strings.Contains(again.Body, `role="status"`) || strings.Contains(again.Body, "created.") {
		t.Errorf("flash shown a second time")
	}
}

func TestInviteLinkShownAfterRedirectOnce(t *testing.T) {
	srv, _, token := authedServer(t)

	redirect := postForm(t, srv, token, "/invite", url.Values{"email": {"new@example.com"}, "role": {"viewer"}})
	page := followRedirect(t, srv, token, redirect)
	for _, want := range []string{"Invite created for new@example.com.", "/register/", "Expires in 72 hours."} {
		if !strings.Contains(page.Body, want) {
			t.Errorf("page does not contain %q", want)
		}
	}

	again := send(t, srv, token, "GET", "/settings", "", "")
	if strings.Contains(again.Body, "/register/") {
		t.Errorf("invite link shown a second time")
	}
}

// A flash the browser sends back damaged, or that is not one of ours, is
// ignored: the page renders normally and the cookie is cleared.
func TestGarbageFlashCookieRendersPage(t *testing.T) {
	srv, _, token := authedServer(t)

	for _, value := range []string{
		"!!not-base64!!",
		base64.RawURLEncoding.EncodeToString([]byte("not json")),
	} {
		req := httptest.NewRequest(http.MethodGet, "/settings", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: token})
		req.AddCookie(&http.Cookie{Name: flashCookie, Value: value})
		page := run(t, srv, req)

		if page.StatusCode != http.StatusOK || !strings.Contains(page.Body, "<h1>Settings</h1>") {
			t.Errorf("cookie %q: status %d, want the settings page; body:\n%s", value, page.StatusCode, page.Body)
		}
		if strings.Contains(page.Body, `role="alert"`) || strings.Contains(page.Body, `role="status"`) {
			t.Errorf("cookie %q: a flash was shown", value)
		}
		if c := flashSetCookie(t, page); !cookieCleared(c) {
			t.Errorf("cookie %q: flash cookie not cleared: %+v", value, c)
		}
	}
}

// The flash must never carry a token, password or API key, only the fields the
// page prefills.
func TestRejectedImporterFlashKeepsNoSecrets(t *testing.T) {
	srv, _, token := authedServer(t)

	redirect := postForm(t, srv, token, "/importers", url.Values{
		"provider":      {"hetzner_cloud"},
		"credentials":   {`{"api_token":"tok-SECRET-123"}`},
		"sync_interval": {"600"},
	})
	c := flashSetCookie(t, redirect)
	if c == nil {
		t.Fatal("no flash cookie set for the rejected importer")
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		t.Fatalf("flash cookie is not base64url: %v", err)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Errorf("flash carries the API token: %s", raw)
	}

	page := followRedirect(t, srv, token, redirect)
	if strings.Contains(page.Body, "SECRET") {
		t.Errorf("token reached the page")
	}
}

func TestRejectedDNSImporterPrefillsDomain(t *testing.T) {
	srv, _, token := authedServer(t)

	redirect := postForm(t, srv, token, "/importers", url.Values{
		"provider":      {"dns_bruteforce"},
		"credentials":   {`{"domain":"example.org"}`},
		"sync_interval": {"600"},
	})
	page := followRedirect(t, srv, token, redirect)
	if !strings.Contains(page.Body, `id="dns_domain"`) || !strings.Contains(page.Body, `value="example.org"`) {
		t.Errorf("domain not prefilled; body:\n%s", page.Body)
	}
	if !strings.Contains(page.Body, `name="sync_interval" id="sync_interval" min="60" style="width: 120px;" value="600"`) {
		t.Errorf("sync interval not prefilled")
	}
}
