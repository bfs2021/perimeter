package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/session"
	"perimeter/ent/user"
	"perimeter/internal/auth"
)

// enableTwoFactor runs setup and confirm for u straight through the auth
// package and returns the secret and recovery codes. The confirming step is the
// current one, so a later login code has to come from a later step.
func enableTwoFactor(t *testing.T, a *auth.Auth, u *ent.User) (string, []string) {
	t.Helper()
	ctx := context.Background()
	secret, err := a.BeginTOTPSetup(ctx, u)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}
	code, err := auth.TOTPCodeAt(secret, time.Now())
	if err != nil {
		t.Fatalf("TOTPCodeAt: %v", err)
	}
	codes, err := a.ConfirmTOTPSetup(ctx, u, code)
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}
	return secret, codes
}

// nextStepCode returns the code for the step after the current one. It is
// always accepted by a fresh login after enableTwoFactor, and never a replay.
func nextStepCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := auth.TOTPCodeAt(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("TOTPCodeAt: %v", err)
	}
	return code
}

// wrongCodeFor returns a six-digit code that is not the next-step code.
func wrongCodeFor(t *testing.T, secret string) string {
	t.Helper()
	if nextStepCode(t, secret) == "000000" {
		return "000001"
	}
	return "000000"
}

// cookieFrom returns the named cookie the response sets, or nil.
func cookieFrom(resp response, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: resp.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// cookieValue returns the value the response sets for name, or "" when it
// sets none.
func cookieValue(resp response, name string) string {
	if c := cookieFrom(resp, name); c != nil {
		return c.Value
	}
	return ""
}

// requestWithCookies sends a form POST, or a GET when form is nil, with the
// given cookies. Unlike send it does not add a session cookie on its own.
func requestWithCookies(t *testing.T, srv *Server, method, path string, form url.Values, cookies ...*http.Cookie) response {
	t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
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

// passwordLogin posts the password step and returns the response.
func passwordLogin(t *testing.T, srv *Server, email, password string) response {
	t.Helper()
	return requestWithCookies(t, srv, "POST", "/login", url.Values{"email": {email}, "password": {password}})
}

// challengeCookie is the perimeter_2fa cookie a password login sets.
func challengeCookie(t *testing.T, resp response) *http.Cookie {
	t.Helper()
	c := cookieFrom(resp, loginChallengeCookie)
	if c == nil || c.Value == "" {
		t.Fatalf("no %s cookie in response", loginChallengeCookie)
	}
	return &http.Cookie{Name: loginChallengeCookie, Value: c.Value}
}

// flashFrom returns the flash cookie a response sets, to pass on to the next page.
func flashFrom(t *testing.T, resp response) *http.Cookie {
	t.Helper()
	c := cookieFrom(resp, flashCookie)
	if c == nil || c.Value == "" {
		t.Fatalf("no flash cookie in response")
	}
	return &http.Cookie{Name: flashCookie, Value: c.Value}
}

// recoveryCodePattern matches an xxxxx-xxxxx recovery code. recoveryPreBlock
// finds the <pre> that holds the codes, so CSS names are not counted.
var (
	recoveryCodePattern = regexp.MustCompile(`\b[a-z2-7]{5}-[a-z2-7]{5}\b`)
	recoveryPreBlock    = regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)
)

// recoveryCodesOnPage returns the codes listed in the recovery page's <pre>.
func recoveryCodesOnPage(t *testing.T, body string) []string {
	t.Helper()
	m := recoveryPreBlock.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("recovery page has no <pre> block; body:\n%s", body)
	}
	return recoveryCodePattern.FindAllString(m[1], -1)
}

func TestLoginWithTwoFactorNeedsSecondStep(t *testing.T) {
	srv, client, _ := authedServer(t)
	ctx := context.Background()
	admin, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}
	secret, _ := enableTwoFactor(t, srv.auth, admin)

	// Pin last_login_at to an old date so a change is easy to see.
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := client.User.UpdateOne(admin).SetLastLoginAt(old).Save(ctx); err != nil {
		t.Fatalf("set last login: %v", err)
	}

	resp := passwordLogin(t, srv, "admin@test.com", "password123")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/2fa" {
		t.Fatalf("password step: status %d location %q, want 303 to /login/2fa", resp.StatusCode, resp.Header.Get("Location"))
	}
	challenge := challengeCookie(t, resp)
	if c := cookieFrom(resp, auth.SessionCookie); c != nil && c.Value != "" {
		t.Fatalf("password step set a session cookie before the second factor")
	}
	if c := cookieFrom(resp, loginChallengeCookie); c == nil || !c.HttpOnly {
		t.Errorf("challenge cookie is not HttpOnly")
	}
	if got, _ := client.User.Get(ctx, admin.ID); got.LastLoginAt == nil || !got.LastLoginAt.Equal(old) {
		t.Errorf("last_login_at changed before the second factor: %v", got.LastLoginAt)
	}

	// The challenge is not a session: presented as one, it is turned away.
	resp = requestWithCookies(t, srv, "GET", "/", nil, &http.Cookie{Name: auth.SessionCookie, Value: challenge.Value})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Errorf("challenge used as session: status %d location %q, want 302 to /login", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp = requestWithCookies(t, srv, "GET", "/login/2fa", nil, challenge)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "Two-factor authentication") {
		t.Fatalf("GET /login/2fa: status %d, body:\n%s", resp.StatusCode, resp.Body)
	}

	resp = requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {nextStepCode(t, secret)}}, challenge)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("correct code: status %d location %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if cookieValue(resp, auth.SessionCookie) == "" {
		t.Error("correct code did not set a session cookie")
	}
	if c := cookieFrom(resp, loginChallengeCookie); c == nil || c.Value != "" || c.Expires.After(time.Now()) {
		t.Errorf("challenge cookie was not cleared after success")
	}
	if got, _ := client.User.Get(ctx, admin.ID); got.LastLoginAt == nil || got.LastLoginAt.Year() == 2000 {
		t.Errorf("last_login_at not updated after the second factor: %v", got.LastLoginAt)
	}
}

func TestLoginWithTwoFactorWrongCodes(t *testing.T) {
	srv, client, _ := authedServer(t)
	ctx := context.Background()
	admin, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}
	secret, _ := enableTwoFactor(t, srv.auth, admin)

	challenge := challengeCookie(t, passwordLogin(t, srv, "admin@test.com", "password123"))
	wrong := wrongCodeFor(t, secret)

	var resp response
	for i := 1; i <= 4; i++ {
		resp = requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {wrong}}, challenge)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/2fa" {
			t.Fatalf("wrong code %d: status %d location %q, want 303 to /login/2fa", i, resp.StatusCode, resp.Header.Get("Location"))
		}
		if cookieValue(resp, auth.SessionCookie) != "" {
			t.Fatalf("wrong code %d set a session cookie", i)
		}
	}
	// The prompt shows the error flash the wrong code left behind.
	page := requestWithCookies(t, srv, "GET", "/login/2fa", nil, challenge, flashFrom(t, resp))
	if !strings.Contains(page.Body, "Invalid code.") {
		t.Errorf("prompt after wrong code does not show the error; body:\n%s", page.Body)
	}

	// The fifth wrong code uses up the challenge and sends the user to sign in again.
	resp = requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {wrong}}, challenge)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("fifth wrong code: status %d location %q, want 303 to /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	page = requestWithCookies(t, srv, "GET", "/login", nil, flashFrom(t, resp))
	if !strings.Contains(page.Body, "Too many attempts. Please sign in again.") {
		t.Errorf("login page after five wrong codes does not explain why; body:\n%s", page.Body)
	}

	resp = requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {nextStepCode(t, secret)}}, challenge)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Errorf("code after the challenge is gone: status %d location %q, want 303 to /login", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLoginRecoveryCodeWorksOnce(t *testing.T) {
	srv, client, _ := authedServer(t)
	ctx := context.Background()
	admin, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}
	_, codes := enableTwoFactor(t, srv.auth, admin)

	challenge := challengeCookie(t, passwordLogin(t, srv, "admin@test.com", "password123"))
	resp := requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {codes[0]}}, challenge)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("recovery code: status %d location %q, want 302 to /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if cookieValue(resp, auth.SessionCookie) == "" {
		t.Error("recovery code did not set a session cookie")
	}

	challenge = challengeCookie(t, passwordLogin(t, srv, "admin@test.com", "password123"))
	resp = requestWithCookies(t, srv, "POST", "/login/2fa", url.Values{"code": {codes[0]}}, challenge)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login/2fa" {
		t.Errorf("reused recovery code: status %d location %q, want 303 to /login/2fa", resp.StatusCode, resp.Header.Get("Location"))
	}
	if cookieValue(resp, auth.SessionCookie) != "" {
		t.Error("reused recovery code set a session cookie")
	}
}

func TestAccountSetupConfirmAndRecoveryPage(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	admin, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}

	resp := postForm(t, srv, token, "/account/2fa/setup", url.Values{})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account/2fa/setup" {
		t.Fatalf("POST setup: status %d location %q, want 303 to /account/2fa/setup", resp.StatusCode, resp.Header.Get("Location"))
	}

	page := send(t, srv, token, "GET", "/account/2fa/setup", "", "")
	body := page.Body
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET setup: status %d, body:\n%s", page.StatusCode, body)
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Error("setup page has no QR code")
	}
	admin, err = client.User.Get(ctx, admin.ID)
	if err != nil {
		t.Fatalf("reload admin: %v", err)
	}
	if !strings.Contains(body, groupSecret(admin.TotpSecret)) {
		t.Errorf("setup page does not show the grouped secret")
	}

	// The QR and the key are secret material, so the page must not be cached.
	if cc := page.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("setup page Cache-Control %q, want no-store", cc)
	}

	resp = postForm(t, srv, token, "/account/2fa/confirm", url.Values{"code": {"000000"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account/2fa/setup" {
		t.Errorf("wrong confirm code: status %d location %q, want 303 to /account/2fa/setup", resp.StatusCode, resp.Header.Get("Location"))
	}

	code, err := auth.TOTPCodeAt(admin.TotpSecret, time.Now())
	if err != nil {
		t.Fatalf("TOTPCodeAt: %v", err)
	}
	resp = postForm(t, srv, token, "/account/2fa/confirm", url.Values{"code": {code}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm: status %d, body:\n%s", resp.StatusCode, resp.Body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("recovery page Cache-Control %q, want no-store", cc)
	}
	if n := len(recoveryCodesOnPage(t, resp.Body)); n != 10 {
		t.Errorf("recovery page shows %d codes, want 10", n)
	}
	if cookieValue(resp, flashCookie) != "" {
		t.Error("recovery codes went into the flash cookie")
	}

	if got, _ := client.User.Get(ctx, admin.ID); !got.TotpEnabled {
		t.Error("two-factor not enabled after confirm")
	}

	account := send(t, srv, token, "GET", "/account", "", "")
	if account.StatusCode != http.StatusOK || !strings.Contains(account.Body, "10 of 10 recovery codes left") {
		t.Errorf("GET /account after enabling: status %d, body does not show 10 codes left", account.StatusCode)
	}

	resp = send(t, srv, token, "GET", "/account/2fa/setup", "", "")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/account" {
		t.Errorf("setup page after enabling: status %d location %q, want 302 to /account", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAccountDisableNeedsPasswordAndCode(t *testing.T) {
	srv, client, token := authedServer(t)
	ctx := context.Background()
	admin, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}
	secret, _ := enableTwoFactor(t, srv.auth, admin)

	disable := func(password, code string) response {
		return postForm(t, srv, token, "/account/2fa/disable", url.Values{"password": {password}, "code": {code}})
	}
	enabled := func() bool {
		got, err := client.User.Get(ctx, admin.ID)
		if err != nil {
			t.Fatalf("reload admin: %v", err)
		}
		return got.TotpEnabled
	}

	resp := disable("wrongpassword", nextStepCode(t, secret))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Errorf("wrong password: status %d location %q, want 303 to /account", resp.StatusCode, resp.Header.Get("Location"))
	}
	if !enabled() {
		t.Fatal("wrong password disabled two-factor")
	}

	resp = disable("password123", wrongCodeFor(t, secret))
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("wrong code: status %d, want 303", resp.StatusCode)
	}
	if !enabled() {
		t.Fatal("wrong code disabled two-factor")
	}

	resp = disable("password123", nextStepCode(t, secret))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/account" {
		t.Fatalf("correct disable: status %d location %q, want 303 to /account", resp.StatusCode, resp.Header.Get("Location"))
	}
	if enabled() {
		t.Error("two-factor still enabled after a correct password and code")
	}
}

func TestAdminResetTwoFactor(t *testing.T) {
	srv, client, tokens := roleServer(t)
	ctx := context.Background()
	member, err := client.User.Query().Where(user.EmailEQ("member@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up member: %v", err)
	}
	admin, err := client.User.Query().Where(user.EmailEQ("admin@test.com")).Only(ctx)
	if err != nil {
		t.Fatalf("look up admin: %v", err)
	}
	enableTwoFactor(t, srv.auth, member)
	enableTwoFactor(t, srv.auth, admin)

	resetPath := "/users/" + strconv.Itoa(member.ID) + "/2fa/reset"
	settings := send(t, srv, tokens[user.RoleAdmin], "GET", "/settings", "", "")
	if !strings.Contains(settings.Body, `action="`+resetPath+`"`) {
		t.Errorf("settings page has no reset form for the member with two-factor on")
	}

	for _, role := range []user.Role{user.RoleMember, user.RoleViewer} {
		if resp := send(t, srv, tokens[role], "POST", resetPath, "", ""); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s reset: status %d, want 403", role, resp.StatusCode)
		}
	}
	if got, _ := client.User.Get(ctx, member.ID); !got.TotpEnabled {
		t.Fatal("a non-admin reset two-factor")
	}

	selfPath := "/users/" + strconv.Itoa(admin.ID) + "/2fa/reset"
	resp := send(t, srv, tokens[user.RoleAdmin], "POST", selfPath, "", "")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Errorf("self reset: status %d location %q, want 303 to /settings", resp.StatusCode, resp.Header.Get("Location"))
	}
	if got, _ := client.User.Get(ctx, admin.ID); !got.TotpEnabled {
		t.Error("admin reset their own two-factor through the settings route")
	}

	// The member's session is also in the database; the reset must delete it.
	memberSessions, err := client.Session.Query().Where(session.HasUserWith(user.IDEQ(member.ID))).Count(ctx)
	if err != nil || memberSessions == 0 {
		t.Fatalf("member sessions before reset: %d (%v), want at least one", memberSessions, err)
	}

	resp = postForm(t, srv, tokens[user.RoleAdmin], resetPath, url.Values{})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("reset: status %d location %q, want 303 to /settings", resp.StatusCode, resp.Header.Get("Location"))
	}
	flash := flashFrom(t, resp)
	if got, _ := client.User.Get(ctx, member.ID); got.TotpEnabled || got.TotpSecret != "" {
		t.Error("two-factor still on after admin reset")
	}
	if n, _ := client.Session.Query().Where(session.HasUserWith(user.IDEQ(member.ID))).Count(ctx); n != 0 {
		t.Errorf("member still has %d sessions after reset", n)
	}

	page := requestWithCookies(t, srv, "GET", "/settings", nil,
		&http.Cookie{Name: auth.SessionCookie, Value: tokens[user.RoleAdmin]}, flash)
	if page.StatusCode != http.StatusOK || !strings.Contains(page.Body, "Two-factor reset for member@test.com. They have been signed out.") {
		t.Errorf("settings after reset does not show the success flash")
	}

	if resp := send(t, srv, tokens[user.RoleAdmin], "POST", "/users/99999/2fa/reset", "", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("reset unknown user: status %d, want 404", resp.StatusCode)
	}
}

func TestAccountPageForEveryRole(t *testing.T) {
	srv, _, tokens := roleServer(t)

	for _, role := range []user.Role{user.RoleAdmin, user.RoleMember, user.RoleViewer} {
		resp := send(t, srv, tokens[role], "GET", "/account", "", "")
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Body, "Two-factor authentication") {
			t.Errorf("%s GET /account: status %d, want the account page; body:\n%s", role, resp.StatusCode, resp.Body)
		}
	}

	// The role users in roleServer have no password, so they are SSO-only:
	// the page says so and setup is refused.
	resp := send(t, srv, tokens[user.RoleMember], "GET", "/account", "", "")
	if !strings.Contains(resp.Body, "single sign-on") {
		t.Errorf("SSO-only account page does not explain where two-factor lives")
	}
	if resp := send(t, srv, tokens[user.RoleMember], "POST", "/account/2fa/setup", "", ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("SSO-only setup: status %d, want 400", resp.StatusCode)
	}
}
