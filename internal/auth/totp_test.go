package auth

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B secret: the ASCII string "12345678901234567890".
var rfcSecret = []byte("12345678901234567890")

var rfcSecretB32 = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rfcSecret)

func TestTOTPCodeRFC6238Vectors(t *testing.T) {
	tests := []struct {
		time int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tt := range tests {
		if got := totpCode(rfcSecret, tt.time/30); got != tt.want {
			t.Errorf("totpCode at T=%d: got %s, want %s", tt.time, got, tt.want)
		}
	}
}

func TestValidateTOTPSkew(t *testing.T) {
	now := time.Unix(1111111109, 0)
	step := now.Unix() / 30

	for _, delta := range []int64{-1, 0, 1} {
		code := totpCode(rfcSecret, step+delta)
		got, ok := ValidateTOTP(rfcSecretB32, code, now, 0)
		if !ok || got != step+delta {
			t.Errorf("skew %d: got (%d, %v), want (%d, true)", delta, got, ok, step+delta)
		}
	}

	for _, delta := range []int64{-2, 2} {
		code := totpCode(rfcSecret, step+delta)
		if _, ok := ValidateTOTP(rfcSecretB32, code, now, 0); ok {
			t.Errorf("skew %d: expected rejection", delta)
		}
	}
}

func TestValidateTOTPReplay(t *testing.T) {
	now := time.Unix(1111111109, 0)
	step := now.Unix() / 30

	used, ok := ValidateTOTP(rfcSecretB32, totpCode(rfcSecret, step), now, 0)
	if !ok {
		t.Fatal("expected current code to be accepted")
	}

	if _, ok := ValidateTOTP(rfcSecretB32, totpCode(rfcSecret, step), now, used); ok {
		t.Error("expected replay of the same step to be rejected")
	}
	if _, ok := ValidateTOTP(rfcSecretB32, totpCode(rfcSecret, step-1), now, used); ok {
		t.Error("expected earlier step to be rejected after a later one was used")
	}
	if _, ok := ValidateTOTP(rfcSecretB32, totpCode(rfcSecret, step+1), now, used); !ok {
		t.Error("expected next step to be accepted")
	}
}

func TestValidateTOTPMalformed(t *testing.T) {
	now := time.Unix(1111111109, 0)
	valid := totpCode(rfcSecret, now.Unix()/30)

	for _, code := range []string{"", "12345", "1234567", "12345a", "+12345", "12 345", "-23456", valid + "0"} {
		if _, ok := ValidateTOTP(rfcSecretB32, code, now, 0); ok {
			t.Errorf("code %q: expected rejection", code)
		}
	}

	if _, ok := ValidateTOTP(rfcSecretB32, " "+valid+" ", now, 0); !ok {
		t.Error("expected surrounding spaces to be trimmed")
	}

	if _, ok := ValidateTOTP("", valid, now, 0); ok {
		t.Error("expected empty secret to be rejected")
	}
}
