package auth_test

import (
	"context"
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"perimeter/ent"
	"perimeter/internal/auth"
)

// codeAt returns the TOTP code for a step, computed the way an authenticator app would.
func codeAt(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	return auth.TOTPCode(key, step)
}

// enableTOTP runs setup and confirm for u. It returns the secret, the recovery
// codes and the step the confirming code was computed for.
func enableTOTP(t *testing.T, a *auth.Auth, u *ent.User) (string, []string, int64) {
	t.Helper()
	ctx := context.Background()

	secret, err := a.BeginTOTPSetup(ctx, u)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}

	step := time.Now().Unix() / 30
	codes, err := a.ConfirmTOTPSetup(ctx, u, codeAt(t, secret, step))
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}
	return secret, codes, step
}

func TestTOTPSetupAndConfirm(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	secret, err := a.BeginTOTPSetup(ctx, u)
	if err != nil {
		t.Fatalf("BeginTOTPSetup: %v", err)
	}

	wrong := "000000"
	if codeAt(t, secret, time.Now().Unix()/30) == wrong {
		wrong = "000001"
	}
	if _, err := a.ConfirmTOTPSetup(ctx, u, wrong); err != auth.ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode for wrong code, got %v", err)
	}

	codes, err := a.ConfirmTOTPSetup(ctx, u, codeAt(t, secret, time.Now().Unix()/30))
	if err != nil {
		t.Fatalf("ConfirmTOTPSetup: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(codes))
	}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Errorf("recovery code %q is not in xxxxx-xxxxx form", c)
		}
	}

	remaining, err := a.RemainingRecoveryCodes(ctx, u)
	if err != nil {
		t.Fatalf("RemainingRecoveryCodes: %v", err)
	}
	if remaining != 10 {
		t.Errorf("expected 10 remaining codes, got %d", remaining)
	}

	if _, err := a.BeginTOTPSetup(ctx, u); err != auth.ErrTOTPAlreadyEnabled {
		t.Errorf("expected ErrTOTPAlreadyEnabled from BeginTOTPSetup, got %v", err)
	}
}

func TestVerifySecondFactorRejectsReplay(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, _, step := enableTOTP(t, a, u)

	// The code that confirmed setup has already used its step.
	if err := a.VerifySecondFactor(ctx, u, codeAt(t, secret, step)); err != auth.ErrInvalidCode {
		t.Errorf("expected replay to be rejected, got %v", err)
	}

	next := codeAt(t, secret, step+1)
	if err := a.VerifySecondFactor(ctx, u, next); err != nil {
		t.Fatalf("VerifySecondFactor with next step: %v", err)
	}
	if err := a.VerifySecondFactor(ctx, u, next); err != auth.ErrInvalidCode {
		t.Errorf("expected replay of next step to be rejected, got %v", err)
	}
}

func TestRecoveryCodeWorksOnce(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, codes, _ := enableTOTP(t, a, u)

	if err := a.VerifySecondFactor(ctx, u, codes[0]); err != nil {
		t.Fatalf("recovery code with dash: %v", err)
	}
	if err := a.VerifySecondFactor(ctx, u, codes[0]); err != auth.ErrInvalidCode {
		t.Errorf("expected reused recovery code to be rejected, got %v", err)
	}
	if err := a.VerifySecondFactor(ctx, u, strings.ToUpper(codes[1])); err != nil {
		t.Errorf("uppercase recovery code: %v", err)
	}
	if err := a.VerifySecondFactor(ctx, u, strings.ReplaceAll(codes[2], "-", "")); err != nil {
		t.Errorf("recovery code without dash: %v", err)
	}

	remaining, err := a.RemainingRecoveryCodes(ctx, u)
	if err != nil {
		t.Fatalf("RemainingRecoveryCodes: %v", err)
	}
	if remaining != 7 {
		t.Errorf("expected 7 remaining codes, got %d", remaining)
	}
}

func TestDisableTOTPNeedsPassword(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, _, step := enableTOTP(t, a, u)

	if err := a.DisableTOTP(ctx, u, "wrongpassword", codeAt(t, secret, step+1)); err != auth.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials with wrong password, got %v", err)
	}
	if _, err := a.BeginTOTPSetup(ctx, u); err != auth.ErrTOTPAlreadyEnabled {
		t.Fatalf("expected two-factor to stay enabled, got %v", err)
	}

	if err := a.DisableTOTP(ctx, u, "password123", codeAt(t, secret, step+1)); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}
	if _, err := a.BeginTOTPSetup(ctx, u); err != nil {
		t.Errorf("expected setup to be possible again after disable, got %v", err)
	}
}

func TestResetTOTPClearsSessions(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	enableTOTP(t, a, u)

	token, err := a.CreateSession(ctx, u)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := a.ResetTOTP(ctx, u.ID); err != nil {
		t.Fatalf("ResetTOTP: %v", err)
	}
	if _, err := a.ValidateSession(ctx, token); err == nil {
		t.Error("expected session to be cleared by ResetTOTP")
	}
	if remaining, _ := a.RemainingRecoveryCodes(ctx, u); remaining != 0 {
		t.Errorf("expected recovery codes to be removed, %d remain", remaining)
	}
	if _, err := a.BeginTOTPSetup(ctx, u); err != nil {
		t.Errorf("expected two-factor to be disabled after reset, got %v", err)
	}
}

func TestLoginChallengeLocksAfterFailedAttempts(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, err := a.CreateLoginChallenge(ctx, u)
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	found, err := a.ValidateLoginChallenge(ctx, token)
	if err != nil {
		t.Fatalf("ValidateLoginChallenge: %v", err)
	}
	if found.ID != u.ID {
		t.Errorf("expected user ID %d, got %d", u.ID, found.ID)
	}

	for i := 0; i < 5; i++ {
		if err := a.FailLoginChallenge(ctx, token); err != nil {
			t.Fatalf("FailLoginChallenge %d: %v", i, err)
		}
	}
	if _, err := a.ValidateLoginChallenge(ctx, token); err != auth.ErrInvalidChallenge {
		t.Errorf("expected ErrInvalidChallenge after 5 failures, got %v", err)
	}

	token, err = a.CreateLoginChallenge(ctx, u)
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	if err := a.DeleteLoginChallenge(ctx, token); err != nil {
		t.Fatalf("DeleteLoginChallenge: %v", err)
	}
	if _, err := a.ValidateLoginChallenge(ctx, token); err != auth.ErrInvalidChallenge {
		t.Errorf("expected ErrInvalidChallenge after delete, got %v", err)
	}
}

func TestLoginSkipsLastLoginForTOTPUser(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	enableTOTP(t, a, u)

	before, err := auth.LastLoginAt(ctx, a, "admin@test.com")
	if err != nil || before == nil {
		t.Fatalf("LastLoginAt before login: %v", err)
	}

	if _, err := a.Login(ctx, "admin@test.com", "password123"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	after, err := auth.LastLoginAt(ctx, a, "admin@test.com")
	if err != nil || after == nil {
		t.Fatalf("LastLoginAt after login: %v", err)
	}
	if !after.Equal(*before) {
		t.Errorf("expected last_login_at unchanged for 2FA user, %v -> %v", before, after)
	}

	if err := a.MarkLogin(ctx, u); err != nil {
		t.Fatalf("MarkLogin: %v", err)
	}
	marked, err := auth.LastLoginAt(ctx, a, "admin@test.com")
	if err != nil || marked == nil {
		t.Fatalf("LastLoginAt after MarkLogin: %v", err)
	}
	if marked.Equal(*before) {
		t.Error("expected MarkLogin to update last_login_at")
	}
}

// wrongCode returns a six-digit code that is not valid for step.
func wrongCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	if codeAt(t, secret, step) == "000000" {
		return "000001"
	}
	return "000000"
}

func TestLoginLockoutAfterTenWrongCodes(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, _, step := enableTOTP(t, a, u)

	// Each wrong code uses up one of a fresh challenge's attempts, so this
	// stays under the per-challenge limit and only the per-user count can lock.
	for i := 0; i < 10; i++ {
		token, err := a.CreateLoginChallenge(ctx, u)
		if err != nil {
			t.Fatalf("CreateLoginChallenge %d: %v", i, err)
		}
		_, err = a.VerifyLoginSecondFactor(ctx, token, wrongCode(t, secret, step))
		want := auth.ErrInvalidCode
		if i == 9 {
			want = auth.ErrTOTPLocked
		}
		if err != want {
			t.Fatalf("wrong code %d: got %v, want %v", i+1, err, want)
		}
	}

	token, err := a.CreateLoginChallenge(ctx, u)
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	if _, err := a.VerifyLoginSecondFactor(ctx, token, codeAt(t, secret, step+1)); err != auth.ErrTOTPLocked {
		t.Errorf("correct code while locked: got %v, want ErrTOTPLocked", err)
	}
}

func TestLoginChallengeAttemptsRunOut(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, _, step := enableTOTP(t, a, u)

	token, err := a.CreateLoginChallenge(ctx, u)
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := a.VerifyLoginSecondFactor(ctx, token, wrongCode(t, secret, step)); err != auth.ErrInvalidCode {
			t.Fatalf("wrong code %d: got %v, want ErrInvalidCode", i+1, err)
		}
	}
	if _, err := a.VerifyLoginSecondFactor(ctx, token, wrongCode(t, secret, step)); err != auth.ErrTooManyAttempts {
		t.Errorf("fifth wrong code: got %v, want ErrTooManyAttempts", err)
	}
	if _, err := a.VerifyLoginSecondFactor(ctx, token, codeAt(t, secret, step+1)); err != auth.ErrInvalidChallenge {
		t.Errorf("challenge after five wrong codes: got %v, want ErrInvalidChallenge", err)
	}
}

func TestSuccessfulLoginResetsFailures(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, _, step := enableTOTP(t, a, u)

	for i := 0; i < 9; i++ {
		token, err := a.CreateLoginChallenge(ctx, u)
		if err != nil {
			t.Fatalf("CreateLoginChallenge: %v", err)
		}
		if _, err := a.VerifyLoginSecondFactor(ctx, token, wrongCode(t, secret, step)); err != auth.ErrInvalidCode {
			t.Fatalf("wrong code %d: got %v, want ErrInvalidCode", i+1, err)
		}
	}

	token, err := a.CreateLoginChallenge(ctx, u)
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	got, err := a.VerifyLoginSecondFactor(ctx, token, codeAt(t, secret, step+1))
	if err != nil {
		t.Fatalf("correct code after nine failures: %v", err)
	}
	if got.ID != u.ID {
		t.Errorf("VerifyLoginSecondFactor returned user %d, want %d", got.ID, u.ID)
	}
	if _, err := a.ValidateLoginChallenge(ctx, token); err != auth.ErrInvalidChallenge {
		t.Errorf("challenge still valid after success: %v", err)
	}

	// The count started over, so nine more failures still do not lock.
	for i := 0; i < 9; i++ {
		token, err := a.CreateLoginChallenge(ctx, u)
		if err != nil {
			t.Fatalf("CreateLoginChallenge: %v", err)
		}
		if _, err := a.VerifyLoginSecondFactor(ctx, token, wrongCode(t, secret, step+2)); err != auth.ErrInvalidCode {
			t.Fatalf("wrong code %d after reset: got %v, want ErrInvalidCode", i+1, err)
		}
	}
}

func TestResetTOTPUnlocks(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, _, step := enableTOTP(t, a, u)
	for i := 0; i < 10; i++ {
		token, err := a.CreateLoginChallenge(ctx, u)
		if err != nil {
			t.Fatalf("CreateLoginChallenge: %v", err)
		}
		_, err = a.VerifyLoginSecondFactor(ctx, token, wrongCode(t, secret, step))
		if i == 9 && err != auth.ErrTOTPLocked {
			t.Fatalf("tenth wrong code: got %v, want ErrTOTPLocked", err)
		}
	}

	if err := a.ResetTOTP(ctx, u.ID); err != nil {
		t.Fatalf("ResetTOTP: %v", err)
	}
	secret, _, step = enableTOTP(t, a, u)

	token, err := a.CreateLoginChallenge(ctx, u)
	if err != nil {
		t.Fatalf("CreateLoginChallenge: %v", err)
	}
	if _, err := a.VerifyLoginSecondFactor(ctx, token, codeAt(t, secret, step+1)); err != nil {
		t.Errorf("login after reset and re-enable: %v", err)
	}
}

func TestAccountFormsShareLockout(t *testing.T) {
	a := newTestAuth(t)
	ctx := context.Background()

	u, err := a.Register(ctx, "admin@test.com", "Admin", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	secret, codes, step := enableTOTP(t, a, u)

	// Wrong codes on the account forms count like wrong codes at login, so a
	// stolen session can't guess its way to new recovery codes.
	for i := 0; i < 10; i++ {
		_, err := a.RegenerateRecoveryCodes(ctx, u, wrongCode(t, secret, step))
		want := auth.ErrInvalidCode
		if i == 9 {
			want = auth.ErrTOTPLocked
		}
		if err != want {
			t.Fatalf("wrong code %d: got %v, want %v", i+1, err, want)
		}
	}

	if _, err := a.RegenerateRecoveryCodes(ctx, u, codes[0]); err != auth.ErrTOTPLocked {
		t.Errorf("regenerate while locked: got %v, want ErrTOTPLocked", err)
	}
	if err := a.DisableTOTP(ctx, u, "password123", codes[1]); err != auth.ErrTOTPLocked {
		t.Errorf("disable while locked: got %v, want ErrTOTPLocked", err)
	}
}
