package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"perimeter/ent/user"
)

func TestRescanTargetFlashesAndShowsRequest(t *testing.T) {
	srv, client, token := authedServer(t)
	id := importTargets(t, client, "rescan.example.com")["rescan.example.com"]
	path := "/targets/" + strconv.Itoa(id)

	redirect := postForm(t, srv, token, path+"/rescan", url.Values{})
	if loc := redirect.Header.Get("Location"); loc != path {
		t.Fatalf("Location = %q, want %q", loc, path)
	}
	page := followRedirect(t, srv, token, redirect)
	if !strings.Contains(page.Body, "Rescan queued for rescan.example.com.") {
		t.Errorf("success flash missing; body:\n%s", page.Body)
	}
	if !strings.Contains(page.Body, "Rescan requested") {
		t.Errorf("target page does not show the pending rescan")
	}
}

func TestRescanTargetCooldownFlash(t *testing.T) {
	srv, client, token := authedServer(t)
	id := importTargets(t, client, "again.example.com")["again.example.com"]
	path := "/targets/" + strconv.Itoa(id) + "/rescan"

	postForm(t, srv, token, path, url.Values{})
	page := followRedirect(t, srv, token, postForm(t, srv, token, path, url.Values{}))
	if !regexp.MustCompile(`again\.example\.com was rescanned recently; try again after \d{2}:\d{2}\.`).MatchString(page.Body) {
		t.Errorf("cooldown flash missing; body:\n%s", page.Body)
	}
}

func TestRescanTargetBadAndUnknownIDs(t *testing.T) {
	srv, _, token := authedServer(t)
	if resp := postForm(t, srv, token, "/targets/abc/rescan", url.Values{}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-numeric id: status %d, want 400", resp.StatusCode)
	}
	if resp := postForm(t, srv, token, "/targets/99999/rescan", url.Values{}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown id: status %d, want 404", resp.StatusCode)
	}
}

func TestBulkRescanFlashesQueuedAndCoolingDown(t *testing.T) {
	srv, client, token := authedServer(t)
	ids := importTargets(t, client, "a.example.com", "b.example.com", "c.example.com")
	a, b, c := ids["a.example.com"], ids["b.example.com"], ids["c.example.com"]

	postForm(t, srv, token, "/targets/"+strconv.Itoa(a)+"/rescan", url.Values{})

	redirect := postForm(t, srv, token, "/targets/bulk/rescan", idsForm(a, b, c))
	if redirect.StatusCode != http.StatusSeeOther || redirect.Header.Get("Location") != "/" {
		t.Fatalf("bulk rescan: status %d, Location %q; want 303 to /", redirect.StatusCode, redirect.Header.Get("Location"))
	}
	page := followRedirect(t, srv, token, redirect)
	if !strings.Contains(page.Body, "Rescan queued for 2 targets (1 cooling down).") {
		t.Errorf("bulk flash missing; body:\n%s", page.Body)
	}
}

func TestRescanControlsByRole(t *testing.T) {
	srv, client, tokens := roleServer(t)
	id := importTargets(t, client, "roles.example.com")["roles.example.com"]
	rescanForm := `action="/targets/` + strconv.Itoa(id) + `/rescan"`

	for _, role := range []user.Role{user.RoleAdmin, user.RoleMember} {
		dash := send(t, srv, tokens[role], "GET", "/", "", "")
		if !strings.Contains(dash.Body, "Rescan selected") {
			t.Errorf("%s: dashboard has no bulk rescan button", role)
		}
		page := send(t, srv, tokens[role], "GET", "/targets/"+strconv.Itoa(id), "", "")
		if !strings.Contains(page.Body, rescanForm) {
			t.Errorf("%s: target page has no rescan form", role)
		}
	}

	dash := send(t, srv, tokens[user.RoleViewer], "GET", "/", "", "")
	if strings.Contains(dash.Body, "Rescan selected") {
		t.Errorf("viewer sees the bulk rescan button")
	}
	page := send(t, srv, tokens[user.RoleViewer], "GET", "/targets/"+strconv.Itoa(id), "", "")
	if strings.Contains(page.Body, rescanForm) {
		t.Errorf("viewer sees the rescan form")
	}
}
