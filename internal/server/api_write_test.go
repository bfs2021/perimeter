package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/auditevent"
	"perimeter/ent/user"
	"perimeter/internal/auth"
	"perimeter/internal/storage"
)

// writeCall sends one request with a JSON body through the real router. The
// body may be empty. extra headers are merged in.
func writeCall(t *testing.T, srv *Server, raw, method, path, body string, extra http.Header) response {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range extra {
		req.Header[k] = v
	}
	resp, err := srv.app.Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(out)}
}

// writeToken makes a write-scope token for the user with this email.
func writeToken(t *testing.T, srv *Server, client *ent.Client, email string) string {
	t.Helper()
	return makeAPIToken(t, srv, client, email, apitoken.ScopeWrite)
}

// wantStatus fails the test unless resp has the status and, when code is not
// empty, the error code.
func wantStatus(t *testing.T, resp response, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d; body %s", resp.StatusCode, status, resp.Body)
	}
	if code != "" {
		if got := apiErrorBodyCode(t, resp.Body); got != code {
			t.Errorf("error code %q, want %q", got, code)
		}
	}
}

// auditCount counts the audit rows with this action.
func auditCount(t *testing.T, client *ent.Client, action string) int {
	t.Helper()
	n, err := client.AuditEvent.Query().Where(auditevent.ActionEQ(action)).Count(t.Context())
	if err != nil {
		t.Fatalf("count audit %s: %v", action, err)
	}
	return n
}

// lastAudit returns the newest audit row with this action.
func lastAudit(t *testing.T, client *ent.Client, action string) *ent.AuditEvent {
	t.Helper()
	row, err := client.AuditEvent.Query().
		Where(auditevent.ActionEQ(action)).
		Order(ent.Desc(auditevent.FieldID)).
		First(t.Context())
	if err != nil {
		t.Fatalf("audit row %s: %v", action, err)
	}
	return row
}

// tagNamesOf decodes the tags of a target summary, sorted.
func tagNamesOf(t *testing.T, body string) []string {
	t.Helper()
	var sum struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal([]byte(body), &sum); err != nil {
		t.Fatalf("decode summary: %v\n%s", err, body)
	}
	slices.Sort(sum.Tags)
	return sum.Tags
}

func TestAPIWriteRoutesNeedWriteScope(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := makeAPIToken(t, srv, client, "member@test.com", apitoken.ScopeRead)
	id := strconv.Itoa(ids["a.example.com"])

	cases := []struct {
		method, path, body string
	}{
		{"POST", "/api/v1/targets", `{"targets":["new.example.com"]}`},
		{"PUT", "/api/v1/targets/" + id + "/tags", `{"tags":[]}`},
		{"POST", "/api/v1/targets/" + id + "/tags", `{"tags":["prod"]}`},
		{"DELETE", "/api/v1/targets/" + id + "/tags/prod", ""},
		{"DELETE", "/api/v1/targets/" + id, ""},
		{"POST", "/api/v1/targets/" + id + "/restore", ""},
		{"POST", "/api/v1/targets/" + id + "/rescan", ""},
		{"POST", "/api/v1/rescan", `{"ids":[` + id + `]}`},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := writeCall(t, srv, raw, tc.method, tc.path, tc.body, nil)
			wantStatus(t, resp, http.StatusForbidden, "forbidden")
		})
	}

	// A refused write changes nothing and audits nothing.
	if n := auditCount(t, client, "target.delete"); n != 0 {
		t.Errorf("%d delete audit rows after refused writes", n)
	}
	if live, _ := client.Target.Query().Count(t.Context()); live != 3 {
		t.Errorf("%d targets, want 3", live)
	}
}

func TestAPIWriteChecksRoleLive(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := writeToken(t, srv, client, "member@test.com")
	member := userByEmail(t, client, "member@test.com")

	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets", `{"targets":["x.example.com"]}`, nil), http.StatusOK, "")

	// A demotion applies to the token at once, without revoking it.
	if err := client.User.UpdateOneID(member.ID).SetRole(user.RoleViewer).Exec(t.Context()); err != nil {
		t.Fatalf("demote: %v", err)
	}
	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets", `{"targets":["y.example.com"]}`, nil), http.StatusForbidden, "forbidden")

	// A viewer cannot be given a write token in the first place.
	viewer := userByEmail(t, client, "viewer@test.com")
	if _, _, err := srv.auth.CreateAPIToken(t.Context(), viewer, "w", apitoken.ScopeWrite, nil); err != auth.ErrTokenScope {
		t.Errorf("viewer write token: err %v, want ErrTokenScope", err)
	}
}

func TestAPIImportTargets(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := writeToken(t, srv, client, "member@test.com")

	resp := writeCall(t, srv, raw, "POST", "/api/v1/targets",
		`{"targets":["a.example.com","1.2.3.4","999.999.999.999"]}`, nil)
	wantStatus(t, resp, http.StatusOK, "")
	var out struct {
		Added    []string `json:"added"`
		Existing []string `json:"existing"`
		Restored []string `json:"restored"`
		Invalid  []string `json:"invalid"`
		Targets  []struct {
			ID     int    `json:"id"`
			Input  string `json:"input"`
			Status string `json:"status"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, resp.Body)
	}
	if strings.Join(out.Added, ",") != "a.example.com,1.2.3.4" || strings.Join(out.Invalid, ",") != "999.999.999.999" {
		t.Errorf("added %v invalid %v", out.Added, out.Invalid)
	}
	if !strings.Contains(resp.Body, `"existing":[]`) || !strings.Contains(resp.Body, `"restored":[]`) {
		t.Errorf("empty lists are not []: %s", resp.Body)
	}
	if len(out.Targets) != 2 || out.Targets[0].Status != "added" || out.Targets[0].Input != "a.example.com" || out.Targets[0].ID == 0 {
		t.Errorf("targets %+v", out.Targets)
	}

	row := lastAudit(t, client, "target.import")
	if string(row.Source) != "api" || row.TokenPrefix != raw[:12] || row.ActorEmail != "member@test.com" {
		t.Errorf("audit row source %q prefix %q actor %q", row.Source, row.TokenPrefix, row.ActorEmail)
	}

	// Importing again reports them as existing; a soft-deleted one is restored.
	ctx := t.Context()
	if err := storage.NewEntStorage(client).DeleteTarget(ctx, out.Targets[1].ID); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	resp = writeCall(t, srv, raw, "POST", "/api/v1/targets", `{"targets":["a.example.com","1.2.3.4"]}`, nil)
	wantStatus(t, resp, http.StatusOK, "")
	if !strings.Contains(resp.Body, `"existing":["a.example.com"]`) || !strings.Contains(resp.Body, `"restored":["1.2.3.4"]`) {
		t.Errorf("second import: %s", resp.Body)
	}
}

func TestAPIImportRejectsBadBodies(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := writeToken(t, srv, client, "member@test.com")

	tooMany := make([]string, maxAPIImportTargets+1)
	for i := range tooMany {
		tooMany[i] = "h" + strconv.Itoa(i) + ".example.com"
	}
	big, err := json.Marshal(importBody{Targets: tooMany})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"not json":   `targets: [`,
		"no targets": `{}`,
		"empty":      `{"targets":[]}`,
		"too many":   string(big),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := writeCall(t, srv, raw, "POST", "/api/v1/targets", body, nil)
			wantStatus(t, resp, http.StatusBadRequest, "invalid_request")
		})
	}
	if n := auditCount(t, client, "target.import"); n != 0 {
		t.Errorf("%d import audit rows for rejected bodies", n)
	}
}

func TestAPITargetTags(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	createTags(t, client, "web")
	raw := writeToken(t, srv, client, "member@test.com")
	path := "/api/v1/targets/" + strconv.Itoa(ids["a.example.com"]) + "/tags"

	resp := writeCall(t, srv, raw, "PUT", path, `{"tags":["web"]}`, nil)
	wantStatus(t, resp, http.StatusOK, "")
	if got := tagNamesOf(t, resp.Body); !slices.Equal(got, []string{"web"}) {
		t.Errorf("after set: %v, want [web]", got)
	}

	resp = writeCall(t, srv, raw, "POST", path, `{"tags":["prod","web"]}`, nil)
	wantStatus(t, resp, http.StatusOK, "")
	if got := tagNamesOf(t, resp.Body); !slices.Equal(got, []string{"prod", "web"}) {
		t.Errorf("after add: %v, want [prod web]", got)
	}

	resp = writeCall(t, srv, raw, "DELETE", path+"/prod", "", nil)
	wantStatus(t, resp, http.StatusOK, "")
	if got := tagNamesOf(t, resp.Body); !slices.Equal(got, []string{"web"}) {
		t.Errorf("after remove: %v, want [web]", got)
	}
	if row := lastAudit(t, client, "target.tags"); row.Detail != "tags removed prod" || string(row.Source) != "api" {
		t.Errorf("audit row %+v", row)
	}

	// Unknown tags are refused in every form; tags are made by admins.
	wantStatus(t, writeCall(t, srv, raw, "PUT", path, `{"tags":["nope"]}`, nil), http.StatusBadRequest, "invalid_request")
	wantStatus(t, writeCall(t, srv, raw, "POST", path, `{"tags":["nope"]}`, nil), http.StatusBadRequest, "invalid_request")
	wantStatus(t, writeCall(t, srv, raw, "DELETE", path+"/nope", "", nil), http.StatusBadRequest, "invalid_request")

	// A missing tags key is refused, so {} cannot clear the tags by accident.
	wantStatus(t, writeCall(t, srv, raw, "PUT", path, `{}`, nil), http.StatusBadRequest, "invalid_request")

	resp = writeCall(t, srv, raw, "PUT", path, `{"tags":[]}`, nil)
	wantStatus(t, resp, http.StatusOK, "")
	if !strings.Contains(resp.Body, `"tags":[]`) {
		t.Errorf("cleared tags body: %s", resp.Body)
	}

	wantStatus(t, writeCall(t, srv, raw, "PUT", "/api/v1/targets/99999/tags", `{"tags":[]}`, nil), http.StatusNotFound, "not_found")
}

func TestAPIDeleteAndRestoreTarget(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := writeToken(t, srv, client, "member@test.com")
	id := strconv.Itoa(ids["a.example.com"])
	path := "/api/v1/targets/" + id

	resp := writeCall(t, srv, raw, "DELETE", path, "", nil)
	wantStatus(t, resp, http.StatusNoContent, "")
	if resp.Body != "" {
		t.Errorf("204 has a body: %q", resp.Body)
	}
	getAPI(t, srv, raw, path, http.StatusNotFound, nil)
	wantStatus(t, writeCall(t, srv, raw, "DELETE", path, "", nil), http.StatusNotFound, "not_found")

	resp = writeCall(t, srv, raw, "POST", path+"/restore", "", nil)
	wantStatus(t, resp, http.StatusOK, "")
	var sum struct {
		ID    int    `json:"id"`
		Input string `json:"input"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &sum); err != nil {
		t.Fatalf("decode restore: %v", err)
	}
	if sum.ID != ids["a.example.com"] || sum.Input != "a.example.com" || strings.Contains(resp.Body, `"deleted_at"`) {
		t.Errorf("restored summary %s", resp.Body)
	}
	getAPI(t, srv, raw, path, http.StatusOK, nil)

	// A live target has nothing to restore.
	wantStatus(t, writeCall(t, srv, raw, "POST", path+"/restore", "", nil), http.StatusNotFound, "not_found")

	for _, action := range []string{"target.delete", "target.restore"} {
		if n := auditCount(t, client, action); n != 1 {
			t.Errorf("%s audit rows %d, want 1", action, n)
		}
	}
	if row := lastAudit(t, client, "target.restore"); string(row.Source) != "api" || row.TokenPrefix != raw[:12] {
		t.Errorf("restore audit source %q prefix %q", row.Source, row.TokenPrefix)
	}
}

func TestAPIRescanTarget(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := writeToken(t, srv, client, "member@test.com")
	path := "/api/v1/targets/" + strconv.Itoa(ids["a.example.com"]) + "/rescan"

	resp := writeCall(t, srv, raw, "POST", path, "", nil)
	wantStatus(t, resp, http.StatusAccepted, "")
	if strings.TrimSpace(resp.Body) != `{"status":"queued"}` {
		t.Errorf("queued body %s", resp.Body)
	}

	// The default cooldown is ten minutes, so a second request is refused
	// with the time to wait.
	resp = writeCall(t, srv, raw, "POST", path, "", nil)
	wantStatus(t, resp, http.StatusAccepted, "")
	if !strings.Contains(resp.Body, `"status":"cooling_down"`) || !strings.Contains(resp.Body, `"retry_at":"`) {
		t.Errorf("cooling body %s", resp.Body)
	}
	retry, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || retry < 1 || retry > int(defaultRescanCooldown/time.Second) {
		t.Errorf("Retry-After %q, want seconds within the cooldown", resp.Header.Get("Retry-After"))
	}

	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets/99999/rescan", "", nil), http.StatusNotFound, "not_found")

	if err := storage.NewEntStorage(client).DeleteTarget(t.Context(), ids["b.example.com"]); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets/"+strconv.Itoa(ids["b.example.com"])+"/rescan", "", nil),
		http.StatusNotFound, "not_found")
}

func TestAPIRescanTargets(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := writeToken(t, srv, client, "member@test.com")
	b := strconv.Itoa(ids["b.example.com"])
	c := strconv.Itoa(ids["c.example.com"])

	resp := writeCall(t, srv, raw, "POST", "/api/v1/rescan", `{"ids":[`+b+`,`+c+`,99999]}`, nil)
	wantStatus(t, resp, http.StatusAccepted, "")
	var out struct {
		Queued      []int `json:"queued"`
		CoolingDown []struct {
			ID      int       `json:"id"`
			RetryAt time.Time `json:"retry_at"`
		} `json:"cooling_down"`
		NotFound []int `json:"not_found"`
	}
	if err := json.Unmarshal([]byte(resp.Body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !slices.Equal(out.Queued, []int{ids["b.example.com"], ids["c.example.com"]}) || !slices.Equal(out.NotFound, []int{99999}) || len(out.CoolingDown) != 0 {
		t.Errorf("first rescan %+v", out)
	}

	// Asking again inside the cooldown lists the targets as cooling down.
	resp = writeCall(t, srv, raw, "POST", "/api/v1/rescan", `{"ids":[`+b+`]}`, nil)
	wantStatus(t, resp, http.StatusAccepted, "")
	if !strings.Contains(resp.Body, `"queued":[]`) || !strings.Contains(resp.Body, `"cooling_down":[{"id":`+b) {
		t.Errorf("second rescan %s", resp.Body)
	}

	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/rescan", `{"ids":[]}`, nil), http.StatusBadRequest, "invalid_request")
	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/rescan", `{}`, nil), http.StatusBadRequest, "invalid_request")

	ids501 := make([]int, 501)
	for i := range ids501 {
		ids501[i] = i + 1
	}
	big, err := json.Marshal(rescanBody{IDs: ids501})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/rescan", string(big), nil), http.StatusBadRequest, "invalid_request")
}

func TestAPIIdempotentReplay(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := writeToken(t, srv, client, "member@test.com")
	key := http.Header{"Idempotency-Key": {"import-1"}}
	body := `{"targets":["replay.example.com"]}`

	first := writeCall(t, srv, raw, "POST", "/api/v1/targets", body, key)
	wantStatus(t, first, http.StatusOK, "")
	if first.Header.Get("Idempotent-Replayed") != "" {
		t.Error("first answer is marked as a replay")
	}

	second := writeCall(t, srv, raw, "POST", "/api/v1/targets", body, key)
	wantStatus(t, second, http.StatusOK, "")
	if second.Header.Get("Idempotent-Replayed") != "true" {
		t.Errorf("replay header %q, want true", second.Header.Get("Idempotent-Replayed"))
	}
	if second.Body != first.Body {
		t.Errorf("replayed body\n%s\nwant\n%s", second.Body, first.Body)
	}
	if second.Header.Get("Content-Type") != first.Header.Get("Content-Type") {
		t.Errorf("replayed content type %q, want %q", second.Header.Get("Content-Type"), first.Header.Get("Content-Type"))
	}
	if n := auditCount(t, client, "target.import"); n != 1 {
		t.Errorf("%d import audit rows after a replay, want 1", n)
	}
	if n, _ := client.Target.Query().Count(t.Context()); n != 1 {
		t.Errorf("%d targets after a replay, want 1", n)
	}
}

func TestAPIIdempotencyRefusesReuseWithOtherRequest(t *testing.T) {
	srv, client, _ := roleServer(t)
	ids := seedReadData(t, client)
	raw := writeToken(t, srv, client, "member@test.com")
	key := http.Header{"Idempotency-Key": {"reuse-1"}}

	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets", `{"targets":["one.example.com"]}`, key), http.StatusOK, "")

	// The same key with another body, or on another path, is a different request.
	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets", `{"targets":["two.example.com"]}`, key), http.StatusConflict, "conflict")
	rescan := "/api/v1/targets/" + strconv.Itoa(ids["a.example.com"]) + "/rescan"
	resp := writeCall(t, srv, raw, "POST", rescan, "", key)
	wantStatus(t, resp, http.StatusConflict, "conflict")
	if !strings.Contains(resp.Body, "Idempotency-Key reused with a different request") {
		t.Errorf("message %s", resp.Body)
	}
}

func TestAPIIdempotencyKeysAreScopedToToken(t *testing.T) {
	srv, client, _ := roleServer(t)
	first := writeToken(t, srv, client, "member@test.com")
	second := writeToken(t, srv, client, "member@test.com")
	key := http.Header{"Idempotency-Key": {"shared"}}
	body := `{"targets":["scoped.example.com"]}`

	wantStatus(t, writeCall(t, srv, first, "POST", "/api/v1/targets", body, key), http.StatusOK, "")
	resp := writeCall(t, srv, second, "POST", "/api/v1/targets", body, key)
	wantStatus(t, resp, http.StatusOK, "")
	if resp.Header.Get("Idempotent-Replayed") != "" {
		t.Error("another token got the first token's answer")
	}
	if !strings.Contains(resp.Body, `"existing":["scoped.example.com"]`) {
		t.Errorf("second token ran as a new request: %s", resp.Body)
	}
	if n := auditCount(t, client, "target.import"); n != 2 {
		t.Errorf("%d import audit rows, want 2", n)
	}
}

func TestAPIIdempotencyKeyValidation(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := writeToken(t, srv, client, "member@test.com")
	body := `{"targets":["key.example.com"]}`

	tooLong := strings.Repeat("k", 256)
	for name, key := range map[string]string{
		"too long":   tooLong,
		"non-ASCII":  "ключ",
		"tab inside": "a\tb",
	} {
		t.Run(name, func(t *testing.T) {
			resp := writeCall(t, srv, raw, "POST", "/api/v1/targets", body, http.Header{"Idempotency-Key": {key}})
			wantStatus(t, resp, http.StatusBadRequest, "invalid_request")
		})
	}

	// 255 printable characters is the longest accepted key.
	resp := writeCall(t, srv, raw, "POST", "/api/v1/targets", body, http.Header{"Idempotency-Key": {strings.Repeat("k", 255)}})
	wantStatus(t, resp, http.StatusOK, "")
}

func TestAPIIdempotencyOnlyCoversWrites(t *testing.T) {
	srv, client, _ := roleServer(t)
	raw := writeToken(t, srv, client, "member@test.com")

	// A GET with a key is not recorded, so the same key still works for a write.
	get := bearer(raw)
	get.Set("Idempotency-Key", "shared")
	for i := range 2 {
		resp := apiCall(t, srv, "GET", "/api/v1/tags", get)
		wantStatus(t, resp, http.StatusOK, "")
		if resp.Header.Get("Idempotent-Replayed") != "" {
			t.Errorf("GET %d was replayed", i)
		}
	}
	body := `{"targets":["plain.example.com"]}`
	wantStatus(t, writeCall(t, srv, raw, "POST", "/api/v1/targets", body, http.Header{"Idempotency-Key": {"shared"}}), http.StatusOK, "")

	// A write with no key is never recorded, so repeats run again.
	for i := range 2 {
		resp := writeCall(t, srv, raw, "POST", "/api/v1/targets", body, nil)
		wantStatus(t, resp, http.StatusOK, "")
		if resp.Header.Get("Idempotent-Replayed") != "" {
			t.Errorf("keyless write %d was replayed", i)
		}
	}
	if n := auditCount(t, client, "target.import"); n != 3 {
		t.Errorf("%d import audit rows, want 3", n)
	}
}

func TestIdempotencyStoreRefusesInFlightAndReleases(t *testing.T) {
	s := newIdempotencyStore(time.Hour, 10)
	k := idemKey{token: 1, key: "k"}

	e, refusal := s.claim(k, "POST /x aa")
	if refusal != "" || e.done {
		t.Fatalf("first claim: refusal %q done %v", refusal, e.done)
	}
	if _, refusal := s.claim(k, "POST /x aa"); refusal != "request with this Idempotency-Key is still in progress" {
		t.Errorf("claim while in flight: refusal %q", refusal)
	}
	if _, refusal := s.claim(k, "POST /x bb"); refusal != "Idempotency-Key reused with a different request" {
		t.Errorf("claim with another body: refusal %q", refusal)
	}

	// A request that did not produce a stored answer frees the key for a retry.
	s.release(e)
	e, refusal = s.claim(k, "POST /x aa")
	if refusal != "" {
		t.Fatalf("claim after release: refusal %q", refusal)
	}
	s.complete(e, http.StatusOK, "application/json", []byte(`{}`))
	got, refusal := s.claim(k, "POST /x aa")
	if refusal != "" || !got.done || got.status != http.StatusOK || string(got.body) != "{}" {
		t.Errorf("claim after complete: %+v refusal %q", got, refusal)
	}
}

func TestIdempotencyStoreEvictsOldestAndExpires(t *testing.T) {
	s := newIdempotencyStore(time.Hour, 2)
	for _, name := range []string{"a", "b"} {
		e, _ := s.claim(idemKey{token: 1, key: name}, "fp")
		s.complete(e, http.StatusOK, "", nil)
	}
	// A third key pushes out the oldest, "a".
	s.claim(idemKey{token: 1, key: "c"}, "fp")
	if _, refusal := s.claim(idemKey{token: 1, key: "a"}, "fp"); refusal != "" {
		t.Errorf("evicted key refused: %q", refusal)
	}

	// A store whose TTL has already passed forgets a finished entry at once.
	expired := newIdempotencyStore(-time.Hour, 10)
	e, _ := expired.claim(idemKey{token: 1, key: "old"}, "fp")
	expired.complete(e, http.StatusOK, "", nil)
	got, refusal := expired.claim(idemKey{token: 1, key: "old"}, "fp")
	if refusal != "" || got.done {
		t.Errorf("expired entry replayed: refusal %q", refusal)
	}
}

func TestValidIdempotencyKey(t *testing.T) {
	for key, want := range map[string]bool{
		"":                       false,
		"x":                      true,
		"a b":                    true,
		strings.Repeat("x", 255): true,
		strings.Repeat("x", 256): false,
		"\x01":                   false,
		"é":                      false,
	} {
		if got := validIdempotencyKey(key); got != want {
			t.Errorf("validIdempotencyKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestIdempotencyStoreKeepsBodiesUnderByteBudget(t *testing.T) {
	s := newIdempotencyStore(time.Hour, 10)
	s.maxBytes = 10
	for _, name := range []string{"a", "b"} {
		e, _ := s.claim(idemKey{token: 1, key: name}, "fp")
		s.complete(e, http.StatusOK, "", []byte("123456"))
	}
	// "b" pushed the total to 12 bytes, so "a" was dropped.
	if got, _ := s.claim(idemKey{token: 1, key: "a"}, "fp"); got.done {
		t.Error("oldest body kept over the byte budget")
	}
	if got, _ := s.claim(idemKey{token: 1, key: "b"}, "fp"); !got.done {
		t.Error("newest body dropped")
	}
	if s.bytes != 6 {
		t.Errorf("bytes = %d, want 6", s.bytes)
	}
}

func TestIdempotencyDoesNotReplayAuthOrRateLimitAnswers(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError} {
		if replayable(status) {
			t.Errorf("status %d replayable", status)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusAccepted, http.StatusNoContent, http.StatusBadRequest, http.StatusNotFound} {
		if !replayable(status) {
			t.Errorf("status %d not replayable", status)
		}
	}
}
