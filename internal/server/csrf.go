package server

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// crossOriginProtection rejects state-changing requests that a browser sent
// from another origin, the CSRF defence for every POST form (issue #18). It
// reuses net/http's CrossOriginProtection: requests whose Sec-Fetch-Site or
// Origin header shows a cross-site origin are refused, while same-origin
// requests and non-browser clients (no such headers) pass. Safe methods are
// never checked. No tokens, so forms need no hidden field.
//
// The Origin fallback compares against the Host header, so a reverse proxy in
// front of perimeter must preserve Host.
func crossOriginProtection() fiber.Handler {
	cop := http.NewCrossOriginProtection()
	return func(c *fiber.Ctx) error {
		// Bearer-token calls skip the check. A browser never attaches an
		// Authorization header on its own, so these requests can't be forged
		// cross-site, and API clients may run in a browser. Cookie routes stay checked.
		if isBearerPath(c.Path()) && c.Get(fiber.HeaderAuthorization) != "" {
			return c.Next()
		}
		req := &http.Request{
			Method: c.Method(),
			Host:   string(c.Request().Host()),
			Header: http.Header{},
		}
		for _, h := range []string{"Sec-Fetch-Site", "Origin"} {
			if v := c.Get(h); v != "" {
				req.Header.Set(h, v)
			}
		}
		if err := cop.Check(req); err != nil {
			return fiber.NewError(fiber.StatusForbidden, "Cross-origin request blocked")
		}
		return c.Next()
	}
}

// isBearerPath reports whether path is one of the routes that take bearer tokens.
func isBearerPath(path string) bool {
	return strings.HasPrefix(path, "/api/") || path == "/mcp" || strings.HasPrefix(path, "/mcp/")
}
