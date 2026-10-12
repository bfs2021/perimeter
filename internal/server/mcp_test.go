package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"

	"perimeter/ent/apitoken"
	"perimeter/ent/auditevent"
	"perimeter/ent/target"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// bearerTransport adds a bearer token to every request an MCP client makes.
type bearerTransport struct {
	token string
	next  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

// listenMCP serves the router on a loopback port, so an MCP client can use
// real HTTP. It returns the base URL.
func listenMCP(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.app.Listener(ln) }()
	t.Cleanup(func() { _ = srv.app.Shutdown() })
	return "http://" + ln.Addr().String()
}

// mcpClient connects an MCP client over HTTP with the token. The standalone
// SSE stream is off: these requests are answered one POST at a time.
func mcpClient(t *testing.T, base, token string) *mcp.ClientSession {
	t.Helper()
	transport := &mcp.StreamableClientTransport{
		Endpoint:             base + "/mcp",
		HTTPClient:           &http.Client{Transport: bearerTransport{token: token, next: http.DefaultTransport}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "e2e", Version: "1"}, nil).Connect(context.Background(), transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestMCPListsToolsAndCallsSummaryOverHTTP(t *testing.T) {
	srv, client, _ := roleServer(t)
	base := listenMCP(t, srv)
	u := userByEmail(t, client, "member@test.com")
	raw, _, err := srv.auth.CreateAPIToken(t.Context(), u, "mcp", apitoken.ScopeWrite, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	cs := mcpClient(t, base, raw)
	if got := cs.InitializeResult().ServerInfo.Name; got != "perimeter" {
		t.Errorf("server name %q, want perimeter", got)
	}
	if !strings.Contains(cs.InitializeResult().Instructions, "changes_since") {
		t.Errorf("instructions not sent: %q", cs.InitializeResult().Instructions)
	}

	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	for _, want := range []string{"summary", "find_issues", "add_targets", "rescan"} {
		if !slices.Contains(names, want) {
			t.Errorf("tool %s not listed; got %v", want, names)
		}
	}

	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "summary"})
	if err != nil {
		t.Fatalf("CallTool summary: %v", err)
	}
	if res.IsError {
		t.Fatalf("summary is a tool error: %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("summary has no text content")
	}
}

func TestMCPWriteThroughHTTPIsAuditedAsMCP(t *testing.T) {
	srv, client, _ := roleServer(t)
	base := listenMCP(t, srv)
	u := userByEmail(t, client, "admin@test.com")
	raw, _, err := srv.auth.CreateAPIToken(t.Context(), u, "writer", apitoken.ScopeWrite, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	cs := mcpClient(t, base, raw)
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      "add_targets",
		Arguments: map[string]any{"inputs": []string{"e2e.example.net"}},
	})
	if err != nil {
		t.Fatalf("CallTool add_targets: %v", err)
	}
	if res.IsError {
		t.Fatalf("add_targets: %+v", res.Content)
	}

	n, err := client.Target.Query().Where(target.Input("e2e.example.net")).Count(t.Context())
	if err != nil || n != 1 {
		t.Fatalf("target after add_targets: count %d, err %v", n, err)
	}
	ev, err := client.AuditEvent.Query().Where(auditevent.SourceEQ(auditevent.SourceMcp)).Count(t.Context())
	if err != nil || ev == 0 {
		t.Fatalf("no mcp audit rows: count %d, err %v", ev, err)
	}
}

func TestMCPRawPostWithoutTokenIsJSON401(t *testing.T) {
	srv, _, _ := roleServer(t)
	base := listenMCP(t, srv)

	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	req, err := http.NewRequest(http.MethodPost, base+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /mcp: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401; body %s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content type %q, want JSON", ct)
	}
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Error.Code != "unauthorized" {
		t.Errorf("body %s, want the unauthorized error code", raw)
	}
}

func TestMCPRevokedTokenStopsWorking(t *testing.T) {
	srv, client, _ := roleServer(t)
	base := listenMCP(t, srv)
	u := userByEmail(t, client, "member@test.com")
	raw, tok, err := srv.auth.CreateAPIToken(t.Context(), u, "soon-gone", apitoken.ScopeRead, nil)
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	cs := mcpClient(t, base, raw)
	if _, err := cs.ListTools(t.Context(), nil); err != nil {
		t.Fatalf("ListTools before revoke: %v", err)
	}
	if err := srv.auth.RevokeAPIToken(t.Context(), tok.ID, u); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}
	if _, err := cs.ListTools(t.Context(), nil); err == nil {
		t.Fatal("ListTools after revoke succeeded, want an error")
	}
}
