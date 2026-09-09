package guard

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	googleIssuer       = "https://accounts.google.com"
	googleIssuerLegacy = "accounts.google.com"
	googleJWKSURL      = "https://www.googleapis.com/oauth2/v3/certs"
)

var _ TokenValidator = (*GoogleTokenValidator)(nil)

type GoogleTokenValidator struct {
	ClientId string
	verifier *oidc.IDTokenVerifier
	fallback *oidc.IDTokenVerifier
}

// NewGoogleTokenValidator creates a validator for Google ID tokens. The
// verifier accepts both issuer spellings used by Google over the years:
// "https://accounts.google.com" and the legacy "accounts.google.com".
func NewGoogleTokenValidator(clientId string) (*GoogleTokenValidator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, googleIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create google token provider: %w", err)
	}
	config := &oidc.Config{ClientID: clientId}
	return &GoogleTokenValidator{
		ClientId: clientId,
		verifier: provider.Verifier(config),
		fallback: oidc.NewVerifier(googleIssuerLegacy, oidc.NewRemoteKeySet(ctx, googleJWKSURL), config),
	}, nil
}

type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
}

func (g *GoogleTokenValidator) ValidateToken(ctx context.Context, token string) (*User, error) {
	idToken, err := g.verifier.Verify(ctx, token)
	if err != nil {
		idToken, err = g.fallback.Verify(ctx, token)
		if err != nil {
			return nil, err
		}
	}

	var claims googleClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}
	raw, err := rawClaims(idToken)
	if err != nil {
		return nil, err
	}
	if claims.Email == "" {
		return nil, errors.New("missing email")
	}
	if !claims.EmailVerified {
		return nil, errors.New("email is not verified")
	}
	if claims.Sub == "" {
		return nil, errors.New("missing sub")
	}

	return &User{
		Id:            claims.Sub,
		Email:         claims.Email,
		VerifiedEmail: true,
		Sub:           claims.Sub,
		Claims:        raw,
	}, nil
}

// rawClaims decodes the full ID token claim set for consumers that need more
// than the normalized User fields (groups, roles, custom claims).
func rawClaims(idToken *oidc.IDToken) (map[string]any, error) {
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("failed to parse raw claims: %w", err)
	}
	return raw, nil
}
