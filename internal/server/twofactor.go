package server

import (
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"strconv"
	"strings"
	"time"

	"perimeter/ent"
	"perimeter/internal/auth"

	"github.com/gofiber/fiber/v2"
	"rsc.io/qr"
)

// loginChallengeCookie carries the login challenge token between the password
// step and the second factor. No session exists until the code is accepted.
const loginChallengeCookie = "perimeter_2fa"

// totpLockedMessage is shown wherever a code is refused because of the lockout.
const totpLockedMessage = "Too many failed codes. Try again in 15 minutes."

// totpIssuer is the name authenticator apps show next to the code.
const totpIssuer = "Perimeter"

// startSecondFactor parks a password-checked login behind a challenge: it sets
// the challenge cookie and sends the user to the code prompt.
func (s *Server) startSecondFactor(c *fiber.Ctx, u *ent.User) error {
	token, err := s.auth.CreateLoginChallenge(c.Context(), u)
	if err != nil {
		return err
	}

	c.Cookie(&fiber.Cookie{
		Name:     loginChallengeCookie,
		Value:    token,
		HTTPOnly: true,
		Path:     "/",
		MaxAge:   300, // matches the challenge lifetime
		SameSite: "Lax",
		// Only over a TLS connection; c.Protocol() honours X-Forwarded-Proto
		// behind a reverse proxy.
		Secure: c.Protocol() == "https",
	})
	return c.Redirect("/login/2fa", fiber.StatusSeeOther)
}

// clearLoginChallengeCookie expires the challenge cookie. The path has to match
// the one it was set with, or the browser keeps it.
func clearLoginChallengeCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     loginChallengeCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HTTPOnly: true,
		SameSite: "Lax",
		Secure:   c.Protocol() == "https",
	})
}

// handleLogin2FAPage shows the code prompt for a pending login.
func (s *Server) handleLogin2FAPage(c *fiber.Ctx) error {
	_, err := s.auth.ValidateLoginChallenge(c.Context(), c.Cookies(loginChallengeCookie))
	if errors.Is(err, auth.ErrInvalidChallenge) {
		setFlash(c, flash{Kind: "error", Message: "Your sign-in expired. Please sign in again."})
		return c.Redirect("/login")
	}
	if err != nil {
		return err
	}
	return c.Render("views/login_2fa", s.templateData(c, fiber.Map{}), "views/layouts/main")
}

// handleLogin2FA checks the code for a pending login. A wrong code goes back to
// the prompt; a locked or used-up challenge sends the user to sign in again.
func (s *Server) handleLogin2FA(c *fiber.Ctx) error {
	u, err := s.auth.VerifyLoginSecondFactor(c.Context(), c.Cookies(loginChallengeCookie), c.FormValue("code"))
	switch {
	case err == nil:
		clearLoginChallengeCookie(c)
		if err := s.auth.MarkLogin(c.Context(), u); err != nil {
			log.Printf("auth: failed to update last login: %v", err)
		}
		return s.createSessionAndRedirect(c, u)
	case errors.Is(err, auth.ErrInvalidCode):
		setFlash(c, flash{Kind: "error", Message: "Invalid code."})
		return c.Redirect("/login/2fa", fiber.StatusSeeOther)
	case errors.Is(err, auth.ErrTOTPLocked):
		clearLoginChallengeCookie(c)
		setFlash(c, flash{Kind: "error", Message: totpLockedMessage})
	case errors.Is(err, auth.ErrTooManyAttempts):
		clearLoginChallengeCookie(c)
		setFlash(c, flash{Kind: "error", Message: "Too many attempts. Please sign in again."})
	case errors.Is(err, auth.ErrInvalidChallenge):
		clearLoginChallengeCookie(c)
		setFlash(c, flash{Kind: "error", Message: "Your sign-in expired. Please sign in again."})
	default:
		return err
	}
	return c.Redirect("/login", fiber.StatusSeeOther)
}

// --- Account and two-factor setup ---

func (s *Server) handleAccount(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	recoveryLeft := 0
	if u.TotpEnabled {
		n, err := s.auth.RemainingRecoveryCodes(c.Context(), u)
		if err != nil {
			return err
		}
		recoveryLeft = n
	}
	tokens, err := s.auth.ListAPITokens(c.Context(), u.ID)
	if err != nil {
		return err
	}

	return c.Render("views/account", s.templateData(c, fiber.Map{
		"SSOOnly":      u.PasswordHash == nil,
		"RecoveryLeft": recoveryLeft,
		"APITokens":    tokens,
	}), "views/layouts/main")
}

// handleAccountSetup starts setup: it stores a pending secret and sends the user
// to the page with the QR code.
func (s *Server) handleAccountSetup(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	if err := refuseSSOOnly(u); err != nil {
		return err
	}

	if _, err := s.auth.BeginTOTPSetup(c.Context(), u); err != nil {
		if errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
			setFlash(c, flash{Kind: "error", Message: "Two-factor authentication is already enabled."})
			return c.Redirect("/account", fiber.StatusSeeOther)
		}
		return err
	}

	setFlash(c, flash{Kind: "success", Message: "Scan the code with your authenticator app, then enter a code to confirm."})
	return c.Redirect("/account/2fa/setup", fiber.StatusSeeOther)
}

// handleAccountSetupPage shows the QR code and the key for a pending setup. The
// page holds the secret, so it is never cached.
func (s *Server) handleAccountSetupPage(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	if u.TotpEnabled || u.TotpSecret == "" {
		return c.Redirect("/account")
	}

	qrURL, err := qrDataURL(auth.TOTPURI(totpIssuer, u.Email, u.TotpSecret))
	if err != nil {
		return err
	}

	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Render("views/account_setup", s.templateData(c, fiber.Map{
		"QRCode": qrURL,
		"Secret": groupSecret(u.TotpSecret),
	}), "views/layouts/main")
}

// handleAccountConfirm checks the first code from a pending secret and enables
// two-factor. The recovery codes are rendered in this response rather than sent
// through a redirect, so they are shown once and never reach the flash cookie.
func (s *Server) handleAccountConfirm(c *fiber.Ctx) error {
	u := auth.GetUser(c)
	if err := refuseSSOOnly(u); err != nil {
		return err
	}

	codes, err := s.auth.ConfirmTOTPSetup(c.Context(), u, c.FormValue("code"))
	switch {
	case err == nil:
		return s.renderRecoveryCodes(c, codes)
	case errors.Is(err, auth.ErrInvalidCode):
		setFlash(c, flash{Kind: "error", Message: "Invalid code. Check the time on your device and try again."})
		return c.Redirect("/account/2fa/setup", fiber.StatusSeeOther)
	case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		setFlash(c, flash{Kind: "error", Message: "Two-factor authentication is already enabled."})
		return c.Redirect("/account", fiber.StatusSeeOther)
	default:
		return err
	}
}

// handleAccountRecovery replaces all recovery codes after a second-factor check.
func (s *Server) handleAccountRecovery(c *fiber.Ctx) error {
	codes, err := s.auth.RegenerateRecoveryCodes(c.Context(), auth.GetUser(c), c.FormValue("code"))
	switch {
	case err == nil:
		return s.renderRecoveryCodes(c, codes)
	case errors.Is(err, auth.ErrInvalidCode):
		setFlash(c, flash{Kind: "error", Message: "Invalid code."})
	case errors.Is(err, auth.ErrTOTPLocked):
		setFlash(c, flash{Kind: "error", Message: totpLockedMessage})
	default:
		return err
	}
	return c.Redirect("/account", fiber.StatusSeeOther)
}

// handleAccountDisable turns two-factor off after a password and a second factor.
func (s *Server) handleAccountDisable(c *fiber.Ctx) error {
	err := s.auth.DisableTOTP(c.Context(), auth.GetUser(c), c.FormValue("password"), c.FormValue("code"))
	switch {
	case err == nil:
		setFlash(c, flash{Kind: "success", Message: "Two-factor authentication disabled."})
	case errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrInvalidCode):
		setFlash(c, flash{Kind: "error", Message: "Wrong password or code."})
	case errors.Is(err, auth.ErrTOTPLocked):
		setFlash(c, flash{Kind: "error", Message: totpLockedMessage})
	default:
		return err
	}
	return c.Redirect("/account", fiber.StatusSeeOther)
}

// handleResetTOTP is the admin reset for a user who has lost their second
// factor. It also signs that user out everywhere.
func (s *Server) handleResetTOTP(c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid ID")
	}

	// Admins reset their own two-factor from the account page.
	if auth.GetUser(c).ID == id {
		setFlash(c, flash{Kind: "error", Message: "Cannot reset your own two-factor here. Use your account page instead."})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	member, err := s.client.User.Get(c.Context(), id)
	if err != nil {
		if ent.IsNotFound(err) {
			return fiber.NewError(fiber.StatusNotFound, "User not found")
		}
		return err
	}

	if err := s.auth.ResetTOTP(c.Context(), id); err != nil {
		log.Printf("reset two-factor for user %d: %v", id, err)
		setFlash(c, flash{Kind: "error", Message: "Could not reset two-factor. Check the server log for details."})
		return c.Redirect("/settings", fiber.StatusSeeOther)
	}

	s.auditUI(c, "user.2fa_reset", member.Email, "")
	setFlash(c, flash{Kind: "success", Message: "Two-factor reset for " + member.Email + ". They have been signed out."})
	return c.Redirect("/settings", fiber.StatusSeeOther)
}

// renderRecoveryCodes shows a set of recovery codes once. It sends no-store so
// the codes are not kept by the browser or a proxy.
func (s *Server) renderRecoveryCodes(c *fiber.Ctx, codes []string) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Render("views/account_recovery", s.templateData(c, fiber.Map{
		"Codes": codes,
	}), "views/layouts/main")
}

// refuseSSOOnly rejects two-factor requests from accounts that sign in through an
// identity provider, which owns their second factor.
func refuseSSOOnly(u *ent.User) error {
	if u.PasswordHash == nil {
		return fiber.NewError(fiber.StatusBadRequest, "Two-factor is handled by your identity provider")
	}
	return nil
}

// qrDataURL renders text as a QR code and returns it as a PNG data URL.
func qrDataURL(text string) (template.URL, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())), nil
}

// groupSecret splits a base32 secret into groups of four so it is easier to type.
func groupSecret(secret string) string {
	var b strings.Builder
	for i := 0; i < len(secret); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(secret[i:min(i+4, len(secret))])
	}
	return b.String()
}
