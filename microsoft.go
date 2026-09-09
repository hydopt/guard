package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

var _ TokenValidator = (*MicrosoftTokenValidator)(nil)

type MicrosoftTokenValidator struct {
	ClientId string
	verifier *oidc.IDTokenVerifier
	// pinnedTid restricts tokens to a specific tenant (single-tenant mode).
	// Empty for the tenant-independent modes ("common", "organizations",
	// "consumers").
	pinnedTid string
}

const (
	msCommon        = "common"
	msOrganizations = "organizations"
	msConsumers     = "consumers"

	// msBaseURL prefixes the Entra ID v2.0 discovery/token endpoints.
	msBaseURL = "https://login.microsoftonline.com/%s/v2.0"
	// msIssuerTemplate is the issuer placeholder that Entra ID's
	// tenant-independent metadata reports; real tokens substitute the tenant
	// GUID, so exact-issuer matching is impossible for those endpoints.
	msIssuerTemplate = "https://login.microsoftonline.com/{tenantid}/v2.0"
)

var entraGUIDRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// NewMicrosoftTokenValidator creates a validator for Microsoft Entra ID (Azure
// AD) ID tokens.
//
// Pass a tenant ID to restrict sign-in to a single tenant: preferably the
// tenant GUID, or a verified domain such as "contoso.onmicrosoft.com" (which is
// resolved to its GUID during discovery). Pass one of the tenant-independent
// modes to accept users from multiple tenants:
//   - "common": any organizational directory plus personal Microsoft accounts
//   - "organizations": any organizational directory (work and school accounts)
//   - "consumers": personal Microsoft accounts only
//
// Entra ID puts the actual tenant in every token's "iss" claim and its
// discovery metadata sometimes reports the {tenantid} placeholder, so
// exact-issuer matching is unreliable. All modes therefore verify the
// signature and then enforce the tenant chain of trust: the "tid" claim must
// be a GUID and the "iss" claim must be
// "https://login.microsoftonline.com/{tid}/v2.0". Single-tenant mode
// additionally requires tid to be the configured tenant. Guests whose home
// tenant differs from the configured tenant are rejected by design.
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

func newMultiTenantMicrosoftValidator(tenantId, clientId string) *MicrosoftTokenValidator {
	ctx := context.Background()
	keys := oidc.NewRemoteKeySet(ctx, fmt.Sprintf(msBaseURL, tenantId)+"/discovery/v2.0/keys")
	return &MicrosoftTokenValidator{
		ClientId: clientId,
		verifier: oidc.NewVerifier(msIssuerTemplate, keys, &oidc.Config{ClientID: clientId, SkipIssuerCheck: true}),
	}
}

func newSingleTenantMicrosoftValidator(tenantId, clientId string) (*MicrosoftTokenValidator, error) {
	ctx := context.Background()
	meta, err := fetchMicrosoftMetadata(ctx, fmt.Sprintf(msBaseURL, tenantId))
	if err != nil {
		return nil, err
	}
	pinnedTid, err := resolvePinnedTid(tenantId, meta.Issuer)
	if err != nil {
		return nil, err
	}
	return &MicrosoftTokenValidator{
		ClientId:  clientId,
		verifier:  oidc.NewVerifier(msIssuerTemplate, oidc.NewRemoteKeySet(ctx, meta.JWKSURL), &oidc.Config{ClientID: clientId, SkipIssuerCheck: true}),
		pinnedTid: pinnedTid,
	}, nil
}

// resolvePinnedTid pins the token chain of trust to a single tenant. A
// configured GUID is used directly; a configured domain is resolved to the
// GUID from the issued discovery metadata. If the metadata reports the
// {tenantid} placeholder (some Entra tenants do), the GUID cannot be derived
// and the caller must configure it explicitly.
func resolvePinnedTid(tenantId, metadataIssuer string) (string, error) {
	if entraGUIDRe.MatchString(tenantId) {
		return tenantId, nil
	}
	if tid, ok := entraTenantGUID(metadataIssuer); ok {
		return tid, nil
	}
	return "", fmt.Errorf("microsoft token validator: cannot resolve the tenant GUID for %q; configure the tenant GUID explicitly (a verified domain may not be pinned down)", tenantId)
}

// entraTenantGUID extracts the tenant GUID from a concrete Entra ID v2.0
// issuer URL, e.g. "https://login.microsoftonline.com/{guid}/v2.0".
func entraTenantGUID(issuer string) (string, bool) {
	const host = "https://login.microsoftonline.com/"
	issuer = strings.TrimSuffix(issuer, "/")
	if len(issuer) <= len(host)+len("/v2.0") || !strings.HasPrefix(issuer, host) || !strings.HasSuffix(issuer, "/v2.0") {
		return "", false
	}
	tid := issuer[len(host) : len(issuer)-len("/v2.0")]
	if !entraGUIDRe.MatchString(tid) {
		return "", false
	}
	return tid, true
}

// microsoftMetadata is the subset of the Entra ID OpenID discovery document we
// consume.
type microsoftMetadata struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}

func fetchMicrosoftMetadata(ctx context.Context, issuer string) (*microsoftMetadata, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("microsoft token validator: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("microsoft token validator: failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("microsoft token validator: metadata request failed with %s", resp.Status)
	}

	var meta microsoftMetadata
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&meta); err != nil {
		return nil, fmt.Errorf("microsoft token validator: failed to decode metadata: %w", err)
	}
	if meta.Issuer == "" || meta.JWKSURL == "" {
		return nil, errors.New("microsoft token validator: metadata missing issuer or jwks_uri")
	}
	return &meta, nil
}

type microsoftClaims struct {
	Email             string `json:"email"`
	PreferredUsername string `json:"preferred_username"`
	Tid               string `json:"tid"`
	Sub               string `json:"sub"`
	EmailVerified     bool   `json:"email_verified"`
}

func (m *MicrosoftTokenValidator) ValidateToken(ctx context.Context, token string) (*User, error) {
	idToken, err := m.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	var claims microsoftClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}
	if err := validateEntraTenantIssuer(idToken.Issuer, claims.Tid); err != nil {
		return nil, err
	}
	if m.pinnedTid != "" && claims.Tid != m.pinnedTid {
		return nil, fmt.Errorf("token for tenant %q does not match configured tenant %q", claims.Tid, m.pinnedTid)
	}
	raw, err := rawClaims(idToken)
	if err != nil {
		return nil, err
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
		Claims:        raw,
	}, nil
}

// validateEntraTenantIssuer enforces the tenant chain of trust that Entra ID
// requires when exact-issuer matching is impossible: the "tid" claim must be a
// GUID and the "iss" claim must be
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
