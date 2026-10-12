package server

import (
	"strconv"
	"time"

	"perimeter/internal/auth"
	"perimeter/internal/mcpserver"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// defaultAPIRateLimit is how many /api/v1 requests a token may make per minute.
const defaultAPIRateLimit = 120

// setupAPIRoutes mounts /api/v1. It runs before the cookie group is created,
// because that group's middleware would send a bearer request with no cookie
// to the login page. These routes take a bearer token only.
func (s *Server) setupAPIRoutes() {
	api := s.app.Group("/api/v1", auth.RequireAPIToken(s.auth), s.APIRateLimitMiddleware())
	api.Get("/me", s.handleAPIMe)

	// Any other path under /api/v1 gets the JSON 404. Without this it would
	// fall through to the cookie group and redirect to the login page.
	api.Use(func(c *fiber.Ctx) error {
		return apiError(c, fiber.StatusNotFound, "not_found", "no such endpoint")
	})

	s.setupMCPRoute()
}

// mcpVersion is the version the MCP server reports. Nothing sets a build
// version yet, so it is a fixed "dev".
const mcpVersion = "dev"

// setupMCPRoute mounts the MCP endpoint at /mcp. It sits outside the /api/v1
// group but takes the same credentials: a bearer token only, through the same
// per-token limiter.
func (s *Server) setupMCPRoute() {
	h := mcpserver.New(s.svc, s.auth, mcpVersion)
	s.app.All("/mcp", auth.RequireAPIToken(s.auth), s.APIRateLimitMiddleware(), adaptor.HTTPHandler(h))
}

// SetAPIRateLimit sets how many /api/v1 requests a token may make per minute.
// Call it before the server starts answering requests.
func (s *Server) SetAPIRateLimit(n int) {
	s.apiLimiter = limiter.New(limiter.Config{
		Max:        n,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			if tok := auth.GetAPIToken(c); tok != nil {
				return "tok:" + strconv.Itoa(tok.ID)
			}
			return "ip:" + c.IP()
		},
		// The limiter sets Retry-After itself before calling this.
		LimitReached: func(c *fiber.Ctx) error {
			return apiError(c, fiber.StatusTooManyRequests, "rate_limited", "too many requests, wait for the Retry-After delay")
		},
	})
}

// APIRateLimitMiddleware is the per-token limiter for /api/v1. It reads the
// limiter on every request, so SetAPIRateLimit also applies to routes already
// mounted. /mcp can use it too.
func (s *Server) APIRateLimitMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		return s.apiLimiter(c)
	}
}

// apiMe is the reply to GET /api/v1/me.
type apiMe struct {
	Email string     `json:"email"`
	Name  string     `json:"name"`
	Role  string     `json:"role"`
	Token apiMeToken `json:"token"`
}

// apiMeToken describes the token the request was made with. The raw token is
// never sent back.
type apiMeToken struct {
	Name      string     `json:"name"`
	Scope     string     `json:"scope"`
	Prefix    string     `json:"prefix"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (s *Server) handleAPIMe(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	tok := auth.GetAPIToken(c)
	return c.JSON(apiMe{
		Email: u.Email,
		Name:  u.Name,
		Role:  u.Role.String(),
		Token: apiMeToken{
			Name:      tok.Name,
			Scope:     tok.Scope.String(),
			Prefix:    tok.Prefix,
			ExpiresAt: tok.ExpiresAt,
		},
	})
}

// apiError writes the JSON error body the /api/ routes use:
// {"error":{"code":"...","message":"..."}}.
func apiError(c *fiber.Ctx, status int, code, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": fiber.Map{"code": code, "message": msg}})
}

// apiErrorCode is the snake_case error code for an HTTP status.
func apiErrorCode(status int) string {
	switch status {
	case fiber.StatusBadRequest:
		return "invalid_request"
	case fiber.StatusUnauthorized:
		return "unauthorized"
	case fiber.StatusForbidden:
		return "forbidden"
	case fiber.StatusNotFound:
		return "not_found"
	case fiber.StatusConflict:
		return "conflict"
	case fiber.StatusTooManyRequests:
		return "rate_limited"
	}
	if status >= fiber.StatusInternalServerError {
		return "internal"
	}
	return "invalid_request"
}
