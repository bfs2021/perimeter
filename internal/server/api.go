package server

import (
	"strconv"
	"time"

	apidocs "perimeter/api"
	"perimeter/internal/auth"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// defaultAPIRateLimit is how many /api/v1 requests a token may make per minute.
const defaultAPIRateLimit = 120

// setupAPIRoutes mounts /api/v1. It runs before the cookie group is created,
// because that group's middleware would send a bearer request with no cookie
// to the login page. These routes take a bearer token only.
func (s *Server) setupAPIRoutes() {
	// Registered before the token group so a client can read the spec before it
	// has a token.
	s.app.Get("/api/v1/openapi.yaml", handleOpenAPI)

	api := s.app.Group("/api/v1", auth.RequireAPIToken(s.auth), s.APIRateLimitMiddleware())
	api.Get("/me", s.handleAPIMe)

	// Reads: every token scope and every role may call these.
	api.Get("/targets", s.handleAPIListTargets)
	api.Get("/targets/:id", s.handleAPIGetTarget)
	api.Get("/targets/:id/history", s.handleAPITargetHistory)
	api.Get("/tags", s.handleAPIListTags)
	api.Get("/summary", s.handleAPISummary)
	api.Get("/changes", s.handleAPIChanges)

	// Writes need a write token and an admin or member role. The idempotency
	// check runs first, for POST, PUT and DELETE only, so a repeated write gets
	// its first answer back. Every other method passes through to the catch-all.
	api.Use(newIdempotencyStore(idempotencyTTL, idempotencyMaxEntries).middleware())
	writes := auth.RequireAPIWrite()
	api.Post("/targets", writes, s.handleAPIImport)
	api.Put("/targets/:id/tags", writes, s.handleAPISetTags)
	api.Post("/targets/:id/tags", writes, s.handleAPIAddTags)
	api.Delete("/targets/:id/tags/:tag", writes, s.handleAPIRemoveTag)
	api.Delete("/targets/:id", writes, s.handleAPIDeleteTarget)
	api.Post("/targets/:id/restore", writes, s.handleAPIRestoreTarget)
	api.Post("/targets/:id/rescan", writes, s.handleAPIRescanTarget)
	api.Post("/rescan", writes, s.handleAPIRescanTargets)

	// Any other path under /api/v1 gets the JSON 404. Without this it would
	// fall through to the cookie group and redirect to the login page.
	api.Use(func(c *fiber.Ctx) error {
		return apiError(c, fiber.StatusNotFound, "not_found", "no such endpoint")
	})
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

// handleOpenAPI serves the API description. It is public, as the spec
// describes the auth scheme itself.
func handleOpenAPI(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, "application/yaml; charset=utf-8")
	return c.Send(apidocs.OpenAPI)
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
