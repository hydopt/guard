package bearer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var ErrUnauthorized = errors.New("unauthorized")

type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*User, error)
}

type User struct {
	Id            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"emailVerified"`
	Sub           string `json:"sub"`
}

func authenticateUser(r *http.Request, validators []TokenValidator) (*User, error) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth {
		return nil, fmt.Errorf("missing bearer token: %w", ErrUnauthorized)
	}

	for _, validator := range validators {
		if user, err := validator.ValidateToken(r.Context(), token); err == nil {
			return user, err
		}
	}
	return nil, ErrUnauthorized
}
