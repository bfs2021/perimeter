package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpSecretSize = 20
	totpDigits     = 6
	totpPeriod     = 30
	totpSkew       = 1
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret returns a new random TOTP secret, base32-encoded without padding.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretSize)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(b), nil
}

// totpCode computes the RFC 6238 code for a time step (HOTP per RFC 4226, SHA-1).
func totpCode(secret []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1000000)
}

// ValidateTOTP checks a 6-digit code against a base32 secret, accepting one step
// of clock skew either way. Steps at or before lastStep are rejected so a code
// can only be used once. On success it returns the step the code matched.
func ValidateTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if !isSixDigits(code) {
		return 0, false
	}

	key, err := totpEncoding.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return 0, false
	}

	current := now.Unix() / totpPeriod
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if step <= lastStep {
			continue
		}
		if hmac.Equal([]byte(totpCode(key, step)), []byte(code)) {
			return step, true
		}
	}
	return 0, false
}

// TOTPCodeAt returns the code an authenticator app shows for a base32 secret at
// time t. It is for tests and tooling; the server never reveals codes.
func TOTPCodeAt(secret string, t time.Time) (string, error) {
	key, err := totpEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	return totpCode(key, t.Unix()/totpPeriod), nil
}

// TOTPURI returns the otpauth:// URI that authenticator apps import (usually via QR code).
func TOTPURI(issuer, email, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(email)

	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(totpPeriod))

	return "otpauth://totp/" + label + "?" + q.Encode()
}

func isSixDigits(s string) bool {
	if len(s) != totpDigits {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
