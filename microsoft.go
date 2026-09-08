package bearer

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

var _ TokenValidator = (*MicrosoftTokenValidator)(nil)

type MicrosoftTokenValidator struct {
	ClientId string
	Verifier *oidc.IDTokenVerifier
	// multiTenant is set for Entra ID's tenant-independent endpoints
	// ("common", "organizations", "consumers"). The exact-issuer check is
	// skipped and the tid/iss chain of trust is enforced in ValidateToken.
	multiTenant bool
}

const (
	msCommon        = "common"
	msOrganizations = "organizations"
	msConsumers     = "consumers"

	// msIssuerTemplate is the issuer placeholder that Entra ID's
	// tenant-independent metadata reports; real tokens substitute the tenant
	// GUID, so exact-issuer matching is impossible.
	msIssuerTemplate = "https://login.microsoftonline.com/{tenantid}/v2.0"
	// msJwksURL is the tenant-independent signing key endpoint.
	msJwksURL = "https://login.microsoftonline.com/%s/discovery/v2.0/keys"
)

var entraGUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// NewMicrosoftTokenValidator creates a validator for Microsoft Entra ID (Azure
// AD) ID tokens.
//
// Pass a tenant ID to restrict sign-in to a single tenant: either a GUID or a
// verified domain such as "contoso.onmicrosoft.com". Pass one of the
// tenant-independent modes to accept users from multiple tenants:
//   - "common": any organizational directory plus personal Microsoft accounts
//   - "organizations": any organizational directory (work and school accounts)
//   - "consumers": personal Microsoft accounts only
//
// Entra ID puts the actual tenant in every token's "iss" claim, so
// multi-tenant modes cannot use exact-issuer verification; this validator
// instead enforces the tenant chain of trust (a GUID "tid" claim matching the
// issuer) after verifying the signature.
func NewMicrosoftTokenValidator(tenantId, clientId string) (*MicrosoftTokenValidator, error) {
	if tenantId == "" {
		return nil, errors.New("microsoft token validator requires a tenant id")
	}
	switch tenantId {
	case msCommon, msOrganizations, msConsumers:
		return newMultiTenantMicrosoftValidator(tenantId, clientId), nil
	default:
		return newSingleTenantMicrosoftValidator(tenantId, clientId)
	}
}

func newSingleTenantMicrosoftValidator(tenantId, clientId string) (*MicrosoftTokenValidator, error) {
	issuer := "https://login.microsoftonline.com/" + tenantId + "/v2.0"
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to create microsoft token provider: %w", err)
	}
	return &MicrosoftTokenValidator{
		ClientId: clientId,
		Verifier: provider.Verifier(&oidc.Config{ClientID: clientId}),
	}, nil
}

func newMultiTenantMicrosoftValidator(tenantId, clientId string) *MicrosoftTokenValidator {
	ctx := context.Background()
	keys := oidc.NewRemoteKeySet(ctx, fmt.Sprintf(msJwksURL, tenantId))
	return &MicrosoftTokenValidator{
		ClientId:    clientId,
		Verifier:    oidc.NewVerifier(msIssuerTemplate, keys, &oidc.Config{ClientID: clientId, SkipIssuerCheck: true}),
		multiTenant: true,
	}
}

type microsoftClaims struct {
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Tid               string `json:"tid"`
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
	if m.multiTenant {
		if err := validateEntraTenantIssuer(idToken.Issuer, claims.Tid); err != nil {
			return nil, err
		}
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

// validateEntraTenantIssuer enforces the tenant chain of trust that Entra ID
// requires for tenant-independent ("common"-style) validation: the "tid" claim
// must be a GUID and the "iss" claim must be
// "https://login.microsoftonline.com/{tid}/v2.0".
func validateEntraTenantIssuer(issuer, tid string) error {
	if tid == "" {
		return errors.New("missing tid")
	}
	if !entraGUIDRe.MatchString(tid) {
		return fmt.Errorf("tid is not a GUID: %q", tid)
	}
	expected := "https://login.microsoftonline.com/" + tid + "/v2.0"
	if !strings.EqualFold(issuer, expected) {
		return fmt.Errorf("issuer %q does not match tenant %q", issuer, tid)
	}
	return nil
}
