package server

import (
	"github.com/gofiber/fiber/v2"
)

// securityHeaders adds the hardening headers to every reply (issue #47): no
// framing, no MIME sniffing, and a CSP that keeps all resources local. The
// views load nothing external, so no host needs to be allowed. It is
// registered before the routes, so redirects, static files and the 404/500
// pages rendered by the error handler carry the headers too.
func securityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderXFrameOptions, "DENY")
		c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
		c.Set(fiber.HeaderReferrerPolicy, "same-origin")
		c.Set(fiber.HeaderContentSecurityPolicy,
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
		return c.Next()
	}
}
