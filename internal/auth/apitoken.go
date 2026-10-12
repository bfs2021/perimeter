package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"perimeter/ent"
	"perimeter/ent/apitoken"
	"perimeter/ent/user"
)

const (
	// apiTokenPrefix marks a raw API token, so a stray value from another
	// credential is rejected before any lookup.
	apiTokenPrefix = "prm_"
	// apiTokenRandomBytes is 200 random bits, which base32-encode to 40 characters.
	apiTokenRandomBytes = 25
	// apiTokenDisplayLen is how much of the raw token is kept as the visible prefix.
	apiTokenDisplayLen = len(apiTokenPrefix) + 8
	apiTokenMaxName    = 100
	// lastUsedThrottle caps how often a busy token writes last_used_at.
	lastUsedThrottle = time.Minute
)

var (
	// ErrTokenInvalid covers unknown, revoked and expired tokens alike, so a
	// caller can't tell which of them it sent.
	ErrTokenInvalid = errors.New("API token is invalid, revoked or expired")
	// ErrTokenScope is returned when a viewer asks for a write token.
	ErrTokenScope  = errors.New("viewers can only create read-only tokens")
	ErrTokenName   = errors.New("token name must be 1 to 100 characters")
	ErrTokenExpiry = errors.New("expiry must be in the future")
)

var apiTokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// CreateAPIToken makes a new token for u. It returns the raw token once; only
// its hash is stored.
func (a *Auth) CreateAPIToken(ctx context.Context, u *ent.User, name string, scope apitoken.Scope, expiresAt *time.Time) (string, *ent.APIToken, error) {
	if err := CheckAPITokenRequest(u, name, scope, expiresAt); err != nil {
		return "", nil, err
	}
	name = strings.TrimSpace(name)

	b := make([]byte, apiTokenRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw := apiTokenPrefix + strings.ToLower(apiTokenEncoding.EncodeToString(b))

	tok, err := a.client.APIToken.Create().
		SetName(name).
		SetScope(scope).
		SetTokenHash(hashToken(raw)).
		SetPrefix(raw[:apiTokenDisplayLen]).
		SetNillableExpiresAt(expiresAt).
		SetUser(u).
		Save(ctx)
	if err != nil {
		return "", nil, err
	}
	return raw, tok, nil
}

// CheckAPITokenRequest validates a token request without creating it, so a
// form can reject bad input before it spends the user's second-factor code.
func CheckAPITokenRequest(u *ent.User, name string, scope apitoken.Scope, expiresAt *time.Time) error {
	if u.Role == user.RoleViewer && scope == apitoken.ScopeWrite {
		return ErrTokenScope
	}
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > apiTokenMaxName {
		return ErrTokenName
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return ErrTokenExpiry
	}
	return nil
}

// ValidateAPIToken returns the user and token behind a raw API token. It refuses
// unknown, revoked and expired tokens with ErrTokenInvalid.
func (a *Auth) ValidateAPIToken(ctx context.Context, raw string) (*ent.User, *ent.APIToken, error) {
	if !strings.HasPrefix(raw, apiTokenPrefix) {
		return nil, nil, ErrTokenInvalid
	}

	tok, err := a.client.APIToken.Query().
		Where(apitoken.TokenHashEQ(hashToken(raw))).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, nil, ErrTokenInvalid
		}
		return nil, nil, err
	}

	now := time.Now()
	if tok.RevokedAt != nil || (tok.ExpiresAt != nil && !now.Before(*tok.ExpiresAt)) {
		return nil, nil, ErrTokenInvalid
	}
	u := tok.Edges.User
	if u == nil {
		return nil, nil, ErrTokenInvalid
	}

	// Recording every call would write on each request; once a minute is enough
	// to show the token is in use. A failed write must not reject the request.
	if tok.LastUsedAt == nil || now.Sub(*tok.LastUsedAt) >= lastUsedThrottle {
		if err := a.client.APIToken.UpdateOne(tok).SetLastUsedAt(now).Exec(ctx); err != nil {
			log.Printf("auth: failed to update API token last use: %v", err)
		} else {
			tok.LastUsedAt = &now
		}
	}
	return u, tok, nil
}

// ListAPITokens returns a user's tokens, newest first. Revoked and expired
// tokens are included so the account page can show their status.
func (a *Auth) ListAPITokens(ctx context.Context, userID int) ([]*ent.APIToken, error) {
	return a.client.APIToken.Query().
		Where(apitoken.HasUserWith(user.IDEQ(userID))).
		Order(ent.Desc(apitoken.FieldCreateTime), ent.Desc(apitoken.FieldID)).
		All(ctx)
}

// ListAllAPITokens returns every user's tokens, newest first, with the owner
// loaded. It is for the admin settings page.
func (a *Auth) ListAllAPITokens(ctx context.Context) ([]*ent.APIToken, error) {
	return a.client.APIToken.Query().
		WithUser().
		Order(ent.Desc(apitoken.FieldCreateTime), ent.Desc(apitoken.FieldID)).
		All(ctx)
}

// RevokeAPIToken revokes a token. The owner may revoke their own token and an
// admin may revoke any. Anyone else, and an unknown id, get ErrTokenInvalid.
// Revoking an already revoked token does nothing.
func (a *Auth) RevokeAPIToken(ctx context.Context, tokenID int, actor *ent.User) error {
	tok, err := a.client.APIToken.Query().
		Where(apitoken.IDEQ(tokenID)).
		WithUser().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrTokenInvalid
		}
		return err
	}

	if actor.Role != user.RoleAdmin && (tok.Edges.User == nil || tok.Edges.User.ID != actor.ID) {
		return ErrTokenInvalid
	}
	if tok.RevokedAt != nil {
		return nil
	}
	return a.client.APIToken.UpdateOne(tok).SetRevokedAt(time.Now()).Exec(ctx)
}
