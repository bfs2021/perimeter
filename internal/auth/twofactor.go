package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/loginchallenge"
	"perimeter/ent/recoverycode"
	"perimeter/ent/session"
	"perimeter/ent/user"

	"golang.org/x/crypto/bcrypt"
)

const (
	recoveryCodeCount    = 10
	recoveryCodeLen      = 10
	recoveryAlphabet     = "abcdefghijklmnopqrstuvwxyz234567"
	challengeTTL         = 5 * time.Minute
	challengeMaxAttempts = 5
	// totpMaxFailures wrong codes across any challenges lock the user out of
	// login two-factor for totpLockout. Challenges alone can be opened without
	// limit by anyone who has the password, so the count lives on the user.
	totpMaxFailures = 10
	totpLockout     = 15 * time.Minute
)

// BeginTOTPSetup generates a new TOTP secret and stores it as pending. Two-factor
// stays disabled until ConfirmTOTPSetup checks a code from the secret.
func (a *Auth) BeginTOTPSetup(ctx context.Context, u *ent.User) (string, error) {
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return "", err
	}
	if cur.TotpEnabled {
		return "", ErrTOTPAlreadyEnabled
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return "", err
	}
	if err := a.client.User.UpdateOne(cur).SetTotpSecret(secret).Exec(ctx); err != nil {
		return "", err
	}
	return secret, nil
}

// ConfirmTOTPSetup checks a code against the pending secret, enables two-factor
// and returns the new recovery codes. The plaintext codes are only returned here.
func (a *Auth) ConfirmTOTPSetup(ctx context.Context, u *ent.User, code string) ([]string, error) {
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if cur.TotpEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}

	step, ok := ValidateTOTP(cur.TotpSecret, code, time.Now(), cur.TotpLastStep)
	if !ok {
		return nil, ErrInvalidCode
	}

	tx, err := a.client.Tx(ctx)
	if err != nil {
		return nil, err
	}
	if err := tx.User.UpdateOneID(cur.ID).
		SetTotpEnabled(true).
		SetTotpLastStep(step).
		Exec(ctx); err != nil {
		return nil, rollback(tx, err)
	}
	codes, err := replaceRecoveryCodes(ctx, tx, cur.ID)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// VerifyLoginSecondFactor checks the second factor for a login challenge and, on
// success, returns the user and retires the challenge. A user locked by repeated
// wrong codes is refused before the code is looked at.
func (a *Auth) VerifyLoginSecondFactor(ctx context.Context, challengeToken, code string) (*ent.User, error) {
	u, err := a.ValidateLoginChallenge(ctx, challengeToken)
	if err != nil {
		return nil, err
	}
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if err := a.verifyWithLockout(ctx, cur, code); err != nil {
		if err != ErrInvalidCode {
			return nil, err
		}
		if err := a.FailLoginChallenge(ctx, challengeToken); err != nil {
			return nil, err
		}
		// FailLoginChallenge deletes the challenge once its attempts run out.
		if _, err := a.ValidateLoginChallenge(ctx, challengeToken); err == ErrInvalidChallenge {
			return nil, ErrTooManyAttempts
		}
		return nil, ErrInvalidCode
	}

	if err := a.client.User.UpdateOneID(cur.ID).
		SetTotpFailures(0).
		ClearTotpLockedUntil().
		Exec(ctx); err != nil {
		return nil, err
	}
	if err := a.DeleteLoginChallenge(ctx, challengeToken); err != nil {
		return nil, err
	}
	return cur, nil
}

// verifyWithLockout is VerifySecondFactor behind the per-user lockout: a locked
// user is refused without checking the code, and a wrong code counts toward the
// lock. The login step and the account forms share it, so a stolen session
// can't guess codes on the account page either.
func (a *Auth) verifyWithLockout(ctx context.Context, cur *ent.User, code string) error {
	if cur.TotpLockedUntil != nil && time.Now().Before(*cur.TotpLockedUntil) {
		return ErrTOTPLocked
	}
	err := a.VerifySecondFactor(ctx, cur, code)
	if err != ErrInvalidCode {
		return err
	}
	locked, rerr := a.recordTOTPFailure(ctx, cur.ID)
	if rerr != nil {
		return rerr
	}
	if locked {
		return ErrTOTPLocked
	}
	return ErrInvalidCode
}

// recordTOTPFailure counts a wrong login code. It locks the user for totpLockout
// once the count reaches totpMaxFailures, and reports whether this call locked them.
func (a *Auth) recordTOTPFailure(ctx context.Context, userID int) (bool, error) {
	cur, err := a.client.User.UpdateOneID(userID).AddTotpFailures(1).Save(ctx)
	if err != nil {
		return false, err
	}
	if cur.TotpFailures < totpMaxFailures {
		return false, nil
	}

	until := time.Now().Add(totpLockout)
	if err := a.client.User.UpdateOneID(userID).
		SetTotpFailures(0).
		SetTotpLockedUntil(until).
		Exec(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// VerifySecondFactor accepts either a TOTP code or an unused recovery code for a
// user with two-factor enabled. Each TOTP step and each recovery code works once.
func (a *Auth) VerifySecondFactor(ctx context.Context, u *ent.User, code string) error {
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return err
	}
	if !cur.TotpEnabled {
		return ErrInvalidCode
	}

	code = strings.TrimSpace(code)
	if isSixDigits(code) {
		step, ok := ValidateTOTP(cur.TotpSecret, code, time.Now(), cur.TotpLastStep)
		if !ok {
			return ErrInvalidCode
		}
		// Conditional update so two concurrent requests can't both use the same step.
		n, err := a.client.User.Update().
			Where(user.IDEQ(cur.ID), user.TotpLastStepLT(step)).
			SetTotpLastStep(step).
			Save(ctx)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrInvalidCode
		}
		return nil
	}

	n, err := a.client.RecoveryCode.Update().
		Where(
			recoverycode.HasUserWith(user.IDEQ(cur.ID)),
			recoverycode.CodeHashEQ(hashToken(normalizeRecoveryCode(code))),
			recoverycode.UsedAtIsNil(),
		).
		SetUsedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInvalidCode
	}
	return nil
}

// VerifyAccountSecondFactor checks a TOTP or recovery code for an action on the
// account page, behind the same lockout as the login and recovery forms.
func (a *Auth) VerifyAccountSecondFactor(ctx context.Context, u *ent.User, code string) error {
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return err
	}
	return a.verifyWithLockout(ctx, cur, code)
}

// DisableTOTP turns two-factor off after checking the password and a second factor.
func (a *Auth) DisableTOTP(ctx context.Context, u *ent.User, password, code string) error {
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return err
	}
	if cur.PasswordHash == nil {
		return ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*cur.PasswordHash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	if err := a.verifyWithLockout(ctx, cur, code); err != nil {
		return err
	}

	tx, err := a.client.Tx(ctx)
	if err != nil {
		return err
	}
	if err := clearTOTP(ctx, tx, cur.ID); err != nil {
		return rollback(tx, err)
	}
	return tx.Commit()
}

// RegenerateRecoveryCodes replaces all recovery codes after a second factor check.
func (a *Auth) RegenerateRecoveryCodes(ctx context.Context, u *ent.User, code string) ([]string, error) {
	cur, err := a.client.User.Get(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if err := a.verifyWithLockout(ctx, cur, code); err != nil {
		return nil, err
	}

	tx, err := a.client.Tx(ctx)
	if err != nil {
		return nil, err
	}
	codes, err := replaceRecoveryCodes(ctx, tx, u.ID)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

// ResetTOTP is the admin reset: it turns two-factor off for a user, drops their
// recovery codes and login challenges, and signs them out of every session.
func (a *Auth) ResetTOTP(ctx context.Context, userID int) error {
	tx, err := a.client.Tx(ctx)
	if err != nil {
		return err
	}
	if err := clearTOTP(ctx, tx, userID); err != nil {
		return rollback(tx, err)
	}
	if _, err := tx.LoginChallenge.Delete().
		Where(loginchallenge.HasUserWith(user.IDEQ(userID))).
		Exec(ctx); err != nil {
		return rollback(tx, err)
	}
	if _, err := tx.Session.Delete().
		Where(session.HasUserWith(user.IDEQ(userID))).
		Exec(ctx); err != nil {
		return rollback(tx, err)
	}
	// Tokens are kept as rows so they still show as revoked in the lists.
	if err := tx.APIToken.Update().
		Where(apitoken.HasUserWith(user.IDEQ(userID)), apitoken.RevokedAtIsNil()).
		SetRevokedAt(time.Now()).
		Exec(ctx); err != nil {
		return rollback(tx, err)
	}
	return tx.Commit()
}

// RemainingRecoveryCodes returns how many unused recovery codes the user has left.
func (a *Auth) RemainingRecoveryCodes(ctx context.Context, u *ent.User) (int, error) {
	return a.client.RecoveryCode.Query().
		Where(
			recoverycode.HasUserWith(user.IDEQ(u.ID)),
			recoverycode.UsedAtIsNil(),
		).
		Count(ctx)
}

// CreateLoginChallenge issues a short-lived token that stands in for the session
// while the second factor is pending. Returns the raw token.
func (a *Auth) CreateLoginChallenge(ctx context.Context, u *ent.User) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	// Challenges that were abandoned are swept here; nothing else expires them.
	if _, err := a.client.LoginChallenge.Delete().
		Where(loginchallenge.ExpiresAtLT(time.Now())).
		Exec(ctx); err != nil {
		return "", err
	}

	_, err = a.client.LoginChallenge.Create().
		SetTokenHash(hashToken(token)).
		SetExpiresAt(time.Now().Add(challengeTTL)).
		SetUser(u).
		Save(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create login challenge: %w", err)
	}

	return token, nil
}

// ValidateLoginChallenge returns the user behind a pending login challenge.
func (a *Auth) ValidateLoginChallenge(ctx context.Context, token string) (*ent.User, error) {
	lc, err := a.client.LoginChallenge.Query().
		Where(
			loginchallenge.TokenHashEQ(hashToken(token)),
			loginchallenge.ExpiresAtGT(time.Now()),
			loginchallenge.AttemptsLT(challengeMaxAttempts),
		).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrInvalidChallenge
		}
		return nil, err
	}

	return lc.Edges.User, nil
}

// FailLoginChallenge counts a wrong second factor against a challenge and deletes
// the challenge once it has used up its attempts.
func (a *Auth) FailLoginChallenge(ctx context.Context, token string) error {
	hash := hashToken(token)
	if _, err := a.client.LoginChallenge.Update().
		Where(loginchallenge.TokenHashEQ(hash)).
		AddAttempts(1).
		Save(ctx); err != nil {
		return err
	}

	_, err := a.client.LoginChallenge.Delete().
		Where(
			loginchallenge.TokenHashEQ(hash),
			loginchallenge.AttemptsGTE(challengeMaxAttempts),
		).
		Exec(ctx)
	return err
}

// DeleteLoginChallenge removes a login challenge once it has been completed.
func (a *Auth) DeleteLoginChallenge(ctx context.Context, token string) error {
	_, err := a.client.LoginChallenge.Delete().
		Where(loginchallenge.TokenHashEQ(hashToken(token))).
		Exec(ctx)
	return err
}

// clearTOTP turns two-factor off for a user inside tx.
func clearTOTP(ctx context.Context, tx *ent.Tx, userID int) error {
	if err := tx.User.UpdateOneID(userID).
		SetTotpEnabled(false).
		ClearTotpSecret().
		SetTotpLastStep(0).
		SetTotpFailures(0).
		ClearTotpLockedUntil().
		Exec(ctx); err != nil {
		return err
	}
	_, err := tx.RecoveryCode.Delete().
		Where(recoverycode.HasUserWith(user.IDEQ(userID))).
		Exec(ctx)
	return err
}

// replaceRecoveryCodes deletes a user's recovery codes and creates a fresh set
// inside tx. It returns the plaintext codes; only their hashes are stored.
func replaceRecoveryCodes(ctx context.Context, tx *ent.Tx, userID int) ([]string, error) {
	if _, err := tx.RecoveryCode.Delete().
		Where(recoverycode.HasUserWith(user.IDEQ(userID))).
		Exec(ctx); err != nil {
		return nil, err
	}

	codes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}

	builders := make([]*ent.RecoveryCodeCreate, 0, len(codes))
	for _, c := range codes {
		builders = append(builders, tx.RecoveryCode.Create().
			SetCodeHash(hashToken(normalizeRecoveryCode(c))).
			SetUserID(userID))
	}
	if err := tx.RecoveryCode.CreateBulk(builders...).Exec(ctx); err != nil {
		return nil, err
	}

	return codes, nil
}

// newRecoveryCodes returns random codes shaped like "xxxxx-xxxxx".
func newRecoveryCodes() ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		b := make([]byte, recoveryCodeLen)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		for j := range b {
			b[j] = recoveryAlphabet[b[j]&31]
		}
		codes[i] = string(b[:5]) + "-" + string(b[5:])
	}
	return codes, nil
}

// normalizeRecoveryCode lowercases a code and drops dashes and spaces, so the
// user can type it with or without the separator and in any case.
func normalizeRecoveryCode(code string) string {
	return strings.NewReplacer("-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(code)))
}
