package guard

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

const googleIssuer = "https://accounts.google.com"

var _ TokenValidator = (*GoogleTokenValidator)(nil)

type GoogleTokenValidator struct {
	// ClientId is the first accepted audience, kept for callers that inspect
	// the validator. Validation accepts every ID in clientIDs.
	ClientId  string
	clientIDs []string
	verifier  *oidc.IDTokenVerifier
}

// NewGoogleTokenValidator creates a validator for Google ID tokens issued to
// any of the given client IDs. Browser sign-in uses a web client, while local
// programs exchanging tokens via POST /auth/token use a desktop client, so the
// validator can accept both audiences.
func NewGoogleTokenValidator(clientIDs ...string) (*GoogleTokenValidator, error) {
	ids := make([]string, 0, len(clientIDs))
	for _, id := range clientIDs {
		if id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("google token validator requires a client id")
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, googleIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create google token provider: %w", err)
	}
	// Audience is checked in ValidateToken so multiple client IDs are accepted.
	config := &oidc.Config{SkipClientIDCheck: true}
	return &GoogleTokenValidator{
		ClientId:  ids[0],
		clientIDs: ids,
		verifier:  provider.Verifier(config),
	}, nil
}

// acceptsAudience reports whether the token was issued to one of the accepted
// client IDs.
func (g *GoogleTokenValidator) acceptsAudience(audience []string) bool {
	ids := g.clientIDs
	if len(ids) == 0 && g.ClientId != "" {
		ids = []string{g.ClientId}
	}
	for _, aud := range audience {
		if slices.Contains(ids, aud) {
			return true
		}
	}
	return false
}

type googleClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Sub           string `json:"sub"`
}

func (g *GoogleTokenValidator) ValidateToken(ctx context.Context, token string) (*User, error) {
	idToken, err := g.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if !g.acceptsAudience(idToken.Audience) {
		return nil, fmt.Errorf("token audience %v is not accepted", idToken.Audience)
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
