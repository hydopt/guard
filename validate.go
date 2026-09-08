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
}

func getAuthToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth != "" {
		return strings.TrimPrefix(auth, "Bearer "), nil
	}

	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		slog.Info("Could not find cookie", "error", err)
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
