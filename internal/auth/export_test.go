package auth

import (
	"context"
	"time"

	"perimeter/ent/user"
)

// Test-only exports for the auth_test package.
var TOTPCode = totpCode

// LastLoginAt returns the stored last_login_at for the user with the given email.
func LastLoginAt(ctx context.Context, a *Auth, email string) (*time.Time, error) {
	u, err := a.client.User.Query().Where(user.EmailEQ(email)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return u.LastLoginAt, nil
}
