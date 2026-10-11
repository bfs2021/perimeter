package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// flashCookie carries a one-shot message across a redirect (issue #43). A
// POST that changes something sets it and answers 303 to a GET page; the next
// page render pops it, so a reload does not show the message again.
const flashCookie = "perimeter_flash"

// maxFlashSize caps the encoded cookie. Browsers keep about 4 KB per cookie,
// and a flash is only ever a sentence or two.
const maxFlashSize = 3000

// flash is the message shown after a redirect. Kind is "success" or "error".
// InviteLink is set only for a new invite. Form holds the non-secret fields of
// a rejected form, so the page can prefill them; tokens, passwords and API keys
// never go in it.
type flash struct {
	Kind       string
	Message    string
	InviteLink string            `json:",omitempty"`
	Form       map[string]string `json:",omitempty"`
}

// setFlash stores f in the flash cookie. If the encoded value is too large it
// drops the prefilled form first, since that is the part that can grow.
func setFlash(c *fiber.Ctx, f flash) {
	value, err := encodeFlash(f)
	if err != nil {
		log.Printf("encode flash: %v", err)
		return
	}
	if len(value) > maxFlashSize {
		f.Form = nil
		if value, err = encodeFlash(f); err != nil {
			log.Printf("encode flash: %v", err)
			return
		}
	}
	c.Cookie(&fiber.Cookie{
		Name:     flashCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   60,
		HTTPOnly: true,
		SameSite: "Lax",
		// Only over a TLS connection; c.Protocol() honours X-Forwarded-Proto
		// behind a reverse proxy.
		Secure: c.Protocol() == "https",
	})
}

// popFlash returns the pending flash and clears the cookie. It returns nil when
// there is none, or when the cookie does not decode (a stale or tampered value
// is ignored rather than failing the page).
func popFlash(c *fiber.Ctx) *flash {
	value := c.Cookies(flashCookie)
	if value == "" {
		return nil
	}
	c.Cookie(&fiber.Cookie{
		Name:     flashCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HTTPOnly: true,
		SameSite: "Lax",
		Secure:   c.Protocol() == "https",
	})

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil
	}
	var f flash
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil
	}
	return &f
}

func encodeFlash(f flash) (string, error) {
	raw, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// formValue is the template func behind prefilled fields. It returns the
// rejected form's value for key, or "" when the page has no rejected form, so
// templates need no nil checks.
func formValue(f *flash, key string) string {
	if f == nil {
		return ""
	}
	return f.Form[key]
}

// formChecked is the template func behind the event checkboxes. With no
// rejected form every box starts ticked, as on a new notifier; otherwise only
// the comma-separated values stored at key are ticked. It takes any so
// templates can pass a notifier.EventType.
func formChecked(f *flash, key string, item any) bool {
	if f == nil || f.Form == nil {
		return true
	}
	return slices.Contains(strings.Split(f.Form[key], ","), fmt.Sprint(item))
}
