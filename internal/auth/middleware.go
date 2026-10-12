package auth

import (
	"errors"
	"strings"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/user"

	"github.com/gofiber/fiber/v2"
)

const (
	// UserKey is the Fiber locals key for the authenticated user.
	UserKey = "user"
	// APITokenKey is the Fiber locals key for the API token used on the request.
	APITokenKey = "api_token"
	// SessionCookie is the name of the session cookie.
	SessionCookie = "perimeter_session"
)

// RequireAuth returns middleware that checks for a valid session cookie
// and loads the user into c.Locals(UserKey).
func RequireAuth(a *Auth) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies(SessionCookie)
		if token == "" {
			return c.Redirect("/login")
		}

		u, err := a.ValidateSession(c.Context(), token)
		if err != nil {
			// Invalid or expired session
			return c.Redirect("/login")
		}

		c.Locals(UserKey, u)
		return c.Next()
	}
}

// RequireRole returns middleware that checks the authenticated user has
// one of the given roles. Must be used after RequireAuth.
func RequireRole(roles ...user.Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u, ok := c.Locals(UserKey).(*ent.User)
		if !ok || u == nil {
			return c.Redirect("/login")
		}

		for _, role := range roles {
			if u.Role == role {
				return c.Next()
			}
		}
		return fiber.ErrForbidden
	}
}

// GetUser retrieves the authenticated user from Fiber locals.
func GetUser(c *fiber.Ctx) *ent.User {
	u, _ := c.Locals(UserKey).(*ent.User)
	return u
}

// bearerScheme is the Authorization prefix for API tokens; the scheme name is
// matched without regard to case.
const bearerScheme = "Bearer "

// RequireAPIToken returns middleware that checks for a valid bearer token and
// loads the user and token into c.Locals(UserKey) and c.Locals(APITokenKey).
// Session cookies are not accepted here.
func RequireAPIToken(a *Auth) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get(fiber.HeaderAuthorization)
		if len(header) <= len(bearerScheme) || !strings.EqualFold(header[:len(bearerScheme)], bearerScheme) {
			return apiError(c, fiber.StatusUnauthorized, "unauthorized", "send a bearer token in the Authorization header")
		}

		u, tok, err := a.ValidateAPIToken(c.Context(), strings.TrimSpace(header[len(bearerScheme):]))
		if err != nil {
			if errors.Is(err, ErrTokenInvalid) {
				return apiError(c, fiber.StatusUnauthorized, "unauthorized", err.Error())
			}
			return err
		}

		c.Locals(UserKey, u)
		c.Locals(APITokenKey, tok)
		return c.Next()
	}
}

// RequireAPIWrite returns middleware that lets a request through only when the
// token has write scope and the user's current role can change data. It must
// run after RequireAPIToken. The role is read live, so a demotion applies at once.
func RequireAPIWrite() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tok := GetAPIToken(c)
		u, _ := c.Locals(UserKey).(*ent.User)
		if tok == nil || u == nil {
			return apiError(c, fiber.StatusUnauthorized, "unauthorized", "send a bearer token in the Authorization header")
		}
		if tok.Scope != apitoken.ScopeWrite {
			return apiError(c, fiber.StatusForbidden, "forbidden", "this token is read-only")
		}
		if u.Role != user.RoleAdmin && u.Role != user.RoleMember {
			return apiError(c, fiber.StatusForbidden, "forbidden", "your role cannot change data")
		}
		return c.Next()
	}
}

// GetAPIToken returns the API token used on the request, or nil when the
// request did not come through RequireAPIToken.
func GetAPIToken(c *fiber.Ctx) *ent.APIToken {
	tok, _ := c.Locals(APITokenKey).(*ent.APIToken)
	return tok
}

// apiError writes the JSON error body the /api/v1 routes use.
func apiError(c *fiber.Ctx, status int, code, msg string) error {
	return c.Status(status).JSON(fiber.Map{"error": fiber.Map{"code": code, "message": msg}})
}
