// Package mcpserver is the MCP endpoint mounted at /mcp. It offers the reads
// and writes of the REST API through the service layer, to clients that
// authenticate with an API token.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"perimeter/ent"
	"perimeter/internal/auth"
	"perimeter/internal/service"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// instructions is sent to every client at initialization. It says what the
// data is and in which order a model should look at it.
const instructions = `Perimeter monitors the external attack surface of the domains and IP addresses it tracks: open ports, SSL Labs grades and certificate expiry, and Content-Security-Policy headers.
Results come from periodic scans, so the data can be hours old. Start with summary for an overview, then use find_issues or list_targets to narrow down, and get_target for the details of one target. Poll changes_since to see what is new since a given time.`

// Handler serves the MCP endpoint. Every request gets a server built for the
// token it carries, so the tools a client sees match what that token may do.
type Handler struct {
	svc     *service.Service
	auth    *auth.Auth
	version string
	// cache keeps the tool schemas across the per-request servers.
	cache  *mcp.SchemaCache
	stream *mcp.StreamableHTTPHandler
}

// New returns the endpoint. version is the server version reported to clients.
func New(svc *service.Service, a *auth.Auth, version string) *Handler {
	h := &Handler{svc: svc, auth: a, version: version, cache: mcp.NewSchemaCache()}
	h.stream = mcp.NewStreamableHTTPHandler(h.serverFor, &mcp.StreamableHTTPOptions{
		// No sessions: each POST carries the token, so the role and token
		// state are read fresh on every call.
		Stateless: true,
		// Plain JSON replies rather than SSE, which the bearer clients here
		// read one POST at a time.
		JSONResponse: true,
	})
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.stream.ServeHTTP(w, r)
}

// serverFor is called by the SDK for each request. The route middleware has
// already rejected a bad token, but the SDK needs the user and token here, so
// the token is validated again. A token revoked in between gets nil, which
// the SDK answers with 400.
func (h *Handler) serverFor(r *http.Request) *mcp.Server {
	u, tok, err := h.auth.ValidateAPIToken(r.Context(), bearerToken(r.Header.Get("Authorization")))
	if err != nil {
		return nil
	}
	return h.newServer(u, tok)
}

// newServer builds the MCP server for one caller. The read tools are always
// listed. The write tools are listed only when the token has write scope and
// the role allows changes, so a read-only caller does not see them at all.
func (h *Handler) newServer(u *ent.User, tok *ent.APIToken) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "perimeter", Version: h.version}, &mcp.ServerOptions{
		Instructions: instructions,
		SchemaCache:  h.cache,
	})
	t := &toolset{
		svc:   h.svc,
		actor: service.Actor{User: u, Source: service.SourceMCP, Token: tok},
	}
	t.addReadTools(srv)
	if service.CanWrite(u, tok) {
		t.addWriteTools(srv)
	}
	return srv
}

// toolset holds what the tool handlers need. actor is the caller of every
// write, so the audit log shows the MCP source with the user and token.
type toolset struct {
	svc   *service.Service
	actor service.Actor
}

// bearerToken returns the token of an Authorization header, or "" when the
// header is not a bearer one. The scheme is matched without case, as the
// route middleware does.
func bearerToken(header string) string {
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

// targetID resolves a target argument, which is either a numeric id or the
// input name of a target. A name is looked up after normalization, so
// "Example.com" finds example.com. Soft-deleted targets resolve too; the
// operation then decides whether they apply.
func (t *toolset) targetID(ctx context.Context, arg string) (int, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return 0, badArg("target", "is required: an id such as 12, or a name such as example.com")
	}
	if id, err := strconv.Atoi(arg); err == nil {
		if id <= 0 {
			return 0, badArg("target", "an id must be a positive number, not %q", arg)
		}
		return id, nil
	}
	id, err := t.svc.FindTargetByInput(ctx, arg)
	if errors.Is(err, service.ErrNotFound) {
		return 0, badArg("target", "no target matches %q", arg)
	}
	return id, err
}

// notFound maps the service's not-found error for a resolved target to an
// argument error that says what was looked for, such as "a live target".
func notFound(arg, want string, err error) error {
	if errors.Is(err, service.ErrNotFound) {
		return badArg("target", "no %s matches %q", want, arg)
	}
	return err
}

// badArg is an argument error. The message names the parameter, which is how
// the model learns what to change; the MCP layer reports it as a tool error.
func badArg(field, format string, args ...any) error {
	return &service.InvalidError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// reply is a tool result: the short text a model reads, plus the typed output
// the SDK sends as structuredContent.
func reply[T any](text string, out T) (*mcp.CallToolResult, T, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
}

// ptr returns a pointer to v, for the optional hints of a tool annotation.
func ptr[T any](v T) *T {
	return &v
}

// noArgs is the input of a tool that takes no parameters.
type noArgs struct{}

// Pagination for list tools. A model reads these lists in its context, so the
// page is kept short.
const (
	defaultPage = 25
	maxPage     = 100
)

// pageLimit applies the default and the cap to a limit argument.
func pageLimit(n int) int {
	switch {
	case n <= 0:
		return defaultPage
	case n > maxPage:
		return maxPage
	}
	return n
}
