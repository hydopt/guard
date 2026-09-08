package bearer

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

var _ TokenValidator = (*MicrosoftTokenValidator)(nil)

type MicrosoftTokenValidator struct {
	ClientId string
	Verifier *oidc.IDTokenVerifier
}

// NewMicrosoftTokenValidator creates a validator for Microsoft Entra ID (Azure AD)
// ID tokens. Pass tenantId "common" to accept users from any Entra ID tenant
// (multi-tenant), or a specific tenant ID to restrict to a single tenant.
func NewMicrosoftTokenValidator(tenantId, clientId string) *MicrosoftTokenValidator {
	issuer := "https://login.microsoftonline.com/" + tenantId + "/v2.0"
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		panic(fmt.Sprintf("failed to create microsoft token provider: %v", err))
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientId})
	return &MicrosoftTokenValidator{ClientId: clientId, Verifier: verifier}
}

type microsoftClaims struct {
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Sub               string `json:"sub"`
	EmailVerified     bool   `json:"email_verified"`
}

func (m *MicrosoftTokenValidator) ValidateToken(ctx context.Context, token string) (*User, error) {
	idToken, err := m.Verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	var claims microsoftClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	email := claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}
	if email == "" {
		return nil, errors.New("missing email")
	}
	if claims.Sub == "" {
		return nil, errors.New("missing sub")
	}

	return &User{
		Id:            idToken.Subject,
		Email:         email,
		VerifiedEmail: true,
		Sub:           idToken.Subject,
	}, nil
}
