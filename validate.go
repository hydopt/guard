package bearer

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

var ErrUnauthorized = errors.New("unauthorized")

const SessionCookieName = "session"

type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*User, error)
}

type User struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"emailVerified"`
	Sub           string `json:"sub"`
	// Claims holds the raw ID token claims (e.g. groups, roles, custom
	// claims). Excluded from JSON marshaling so token internals do not leak
	// into API responses by default.
	Claims map[string]any `json:"-"`
}

// getAuthToken returns the bearer credential from the Authorization header
// (Bearer scheme, case-insensitive per RFC 6750) or the session cookie,
// whichever is present. A non-Bearer Authorization header is treated as an
// error, not silently ignored.
func getAuthToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if len(auth) <= len("Bearer ") || !strings.EqualFold(auth[:len("Bearer ")], "Bearer ") {
			return "", errors.New("unsupported authorization scheme")
		}
		return strings.TrimSpace(auth[len("Bearer "):]), nil
	}

	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		slog.Debug("no session cookie", "error", err)
		return "", err
	}
	return c.Value, nil
}

func authenticateUser(ctx context.Context, token string, validators []TokenValidator) (*User, error) {
	for _, validator := range validators {
		if user, err := validator.ValidateToken(ctx, token); err == nil {
			return user, err
		}
	}
	return nil, ErrUnauthorized
}
