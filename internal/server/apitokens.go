package server

import (
	"context"
	"errors"
	"log"
	"strconv"
	"time"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/internal/auth"

	"github.com/gofiber/fiber/v2"
)

// tokenStatus names a token's state for its badge. A revoked token stays
// revoked even after it has expired.
func tokenStatus(t *ent.APIToken) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.ExpiresAt != nil && !time.Now().Before(*t.ExpiresAt):
		return "expired"
	default:
		return "active"
	}
}

// tokenExpiry turns the expiry choice from the account form into a time. A nil
// time means the token never expires. ok is false for an unknown choice.
func tokenExpiry(choice string, now time.Time) (expiresAt *time.Time, ok bool) {
	var t time.Time
	switch choice {
	case "30d":
		t = now.AddDate(0, 0, 30)
	case "90d":
		t = now.AddDate(0, 0, 90)
	case "1y":
		t = now.AddDate(1, 0, 0)
	case "never":
		return nil, true
	default:
		return nil, false
	}
	return &t, true
}

// handleCreateAPIToken makes a token for the signed-in user and shows the raw
// value once. A user with two-factor on must send a current code first.
func (s *Server) handleCreateAPIToken(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	name := c.FormValue("name")
	scope := apitoken.Scope(c.FormValue("scope"))
	choice := c.FormValue("expires")

	if apitoken.ScopeValidator(scope) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid scope")
	}
	expiresAt, ok := tokenExpiry(choice, time.Now())
	if !ok {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid expiry")
	}

	// A rejected form keeps its non-secret fields. The code and the token never go in the flash.
	reject := func(msg string) error {
		setFlash(c, flash{
			Kind:    "error",
			Message: msg,
			Form:    map[string]string{"name": name, "scope": string(scope), "expires": choice},
		})
		return c.Redirect("/account", fiber.StatusSeeOther)
	}

	// Bad input is refused before the code is checked, so a typo in the name
	// doesn't use up a one-time recovery code or count toward the lockout.
	if err := tokenRequestError(auth.CheckAPITokenRequest(u, name, scope, expiresAt)); err != "" {
		return reject(err)
	}

	if u.TotpEnabled {
		err := s.auth.VerifyAccountSecondFactor(c.Context(), u, c.FormValue("code"))
		switch {
		case err == nil:
		case errors.Is(err, auth.ErrInvalidCode):
			return reject("Invalid code.")
		case errors.Is(err, auth.ErrTOTPLocked):
			return reject(totpLockedMessage)
		default:
			return err
		}
	}

	raw, tok, err := s.auth.CreateAPIToken(c.Context(), u, name, scope, expiresAt)
	if msg := tokenRequestError(err); msg != "" {
		return reject(msg)
	}
	if err != nil {
		return err
	}

	s.auditUI(c, "token.create", tok.Prefix, tok.Name+", "+tok.Scope.String())

	// The raw token is shown once, so the page must not be cached. The snippets
	// use the host the request came in on; there is no configured public URL.
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Render("views/account_token", s.templateData(c, fiber.Map{
		"Token":     raw,
		"TokenName": tok.Name,
		"BaseURL":   c.BaseURL(),
	}), "views/layouts/main")
}

// handleRevokeAPIToken revokes a token from the account page.
func (s *Server) handleRevokeAPIToken(c *fiber.Ctx) error {
	return s.revokeAPIToken(c, "/account")
}

// handleAdminRevokeAPIToken revokes any user's token from the settings page.
func (s *Server) handleAdminRevokeAPIToken(c *fiber.Ctx) error {
	return s.revokeAPIToken(c, "/settings")
}

// revokeAPIToken revokes the token named in the path for the signed-in user.
// RevokeAPIToken decides whether that user may: the owner, or an admin.
func (s *Server) revokeAPIToken(c *fiber.Ctx, back string) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	object, detail := s.tokenLabel(c.Context(), id)
	switch err := s.auth.RevokeAPIToken(c.Context(), id, auth.GetUser(c)); {
	case err == nil:
		s.auditUI(c, "token.revoke", object, detail)
		setFlash(c, flash{Kind: "success", Message: "Token revoked."})
	case errors.Is(err, auth.ErrTokenInvalid):
		// The same message for a missing token and someone else's, so the page
		// doesn't reveal which tokens exist.
		setFlash(c, flash{Kind: "error", Message: "Token not found, or you cannot revoke it."})
	default:
		log.Printf("revoke API token %d: %v", id, err)
		setFlash(c, flash{Kind: "error", Message: "Could not revoke the token. Check the server log for details."})
	}
	return c.Redirect(back, fiber.StatusSeeOther)
}

// tokenLabel names a token for an audit row: its prefix, and the email of its
// owner. A missing token is named by its id.
func (s *Server) tokenLabel(ctx context.Context, id int) (object, detail string) {
	tok, err := s.client.APIToken.Query().
		Where(apitoken.IDEQ(id)).
		WithUser().
		Only(ctx)
	if err != nil {
		return "token " + strconv.Itoa(id), ""
	}
	if tok.Edges.User != nil {
		detail = "owner " + tok.Edges.User.Email
	}
	return tok.Prefix, detail
}

// tokenRequestError is the form message for a token validation error, or ""
// when err is nil or not a validation error.
func tokenRequestError(err error) string {
	switch {
	case errors.Is(err, auth.ErrTokenScope):
		return "Viewers can only create read-only tokens."
	case errors.Is(err, auth.ErrTokenName):
		return "Give the token a name of 1 to 100 characters."
	case errors.Is(err, auth.ErrTokenExpiry):
		return "The expiry must be in the future."
	}
	return ""
}
