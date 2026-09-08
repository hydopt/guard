package bearer

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testKeyID = "test-key-id"

func newTestValidator(t *testing.T, clientId string) (*MicrosoftTokenValidator, *rsa.PrivateKey, string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	s := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: testKeyID, Algorithm: "RS256"},
		},
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.SetIssuer(srv.URL)

	provider, err := oidc.NewProvider(t.Context(), srv.URL)
	require.NoError(t, err)

	return &MicrosoftTokenValidator{
		ClientId: clientId,
		Verifier: provider.Verifier(&oidc.Config{ClientID: clientId}),
	}, priv, srv.URL
}

func signMicrosoftToken(t *testing.T, issuer, clientId string, priv *rsa.PrivateKey, claims map[string]string) string {
	t.Helper()
	claimsJSON := `{
		"iss": "` + issuer + `",
		"aud": "` + clientId + `",
		"sub": "test-sub",
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	for k, v := range claims {
		claimsJSON += `, "` + k + `": "` + v + `"`
	}
	claimsJSON += "}"
	return oidctest.SignIDToken(priv, testKeyID, "RS256", claimsJSON)
}

func TestNewMicrosoftTokenValidatorMultitenantModes(t *testing.T) {
	for _, tenant := range []string{msCommon, msOrganizations, msConsumers} {
		v, err := NewMicrosoftTokenValidator(tenant, "client-id")
		require.NoError(t, err, "tenant %q", tenant)
		require.True(t, v.multiTenant, "tenant %q", tenant)
		require.NotNil(t, v.Verifier)
	}
}

func TestNewMicrosoftTokenValidatorRequiresTenant(t *testing.T) {
	_, err := NewMicrosoftTokenValidator("", "client-id")
	assert.Error(t, err)
}

func TestValidateEntraTenantIssuer(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"
	require.NoError(t, validateEntraTenantIssuer(issuer, tenant))

	t.Run("mismatchedTenant", func(t *testing.T) {
		other := "99999999-8888-7777-6666-555555555555"
		err := validateEntraTenantIssuer("https://login.microsoftonline.com/"+other+"/v2.0", tenant)
		assert.ErrorContains(t, err, "does not match tenant")
	})

	t.Run("missingTid", func(t *testing.T) {
		assert.ErrorContains(t, validateEntraTenantIssuer(issuer, ""), "missing tid")
	})

	t.Run("nonGuidTid", func(t *testing.T) {
		assert.ErrorContains(t, validateEntraTenantIssuer("https://login.microsoftonline.com/demo/v2.0", "demo"), "not a GUID")
	})
}

func newMultiTenantTestValidator(t *testing.T, clientId string) (*MicrosoftTokenValidator, *rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	s := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: priv.Public(), KeyID: testKeyID, Algorithm: "RS256"},
		},
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	s.SetIssuer(srv.URL)

	provider, err := oidc.NewProvider(t.Context(), srv.URL)
	require.NoError(t, err)

	return &MicrosoftTokenValidator{
		ClientId:    clientId,
		Verifier:    provider.Verifier(&oidc.Config{ClientID: clientId, SkipIssuerCheck: true}),
		multiTenant: true,
	}, priv, srv.URL
}

func TestMicrosoftValidateTokenMultitenant(t *testing.T) {
	const clientId = "my-test-client"
	const tenant = "11111111-2222-3333-4444-555555555555"
	v, priv, _ := newMultiTenantTestValidator(t, clientId)
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"

	t.Run("validToken", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"email": "user@example.com", "tid": tenant})
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@example.com", user.Email)
		assert.Equal(t, "test-sub", user.Id)
		assert.Equal(t, "test-sub", user.Sub)
		assert.True(t, user.VerifiedEmail)
	})

	t.Run("wrongTenant", func(t *testing.T) {
		other := "99999999-8888-7777-6666-555555555555"
		token := signMicrosoftToken(t, "https://login.microsoftonline.com/"+other+"/v2.0", clientId, priv, map[string]string{"email": "user@example.com", "tid": tenant})
		_, err := v.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "does not match tenant")
	})

	t.Run("missingTid", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"email": "user@example.com"})
		_, err := v.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "missing tid")
	})

	t.Run("wrongAudience", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, "other-client", priv, map[string]string{"email": "user@example.com", "tid": tenant})
		_, err := v.ValidateToken(t.Context(), token)
		assert.Error(t, err)
	})
}

func TestMicrosoftValidateToken(t *testing.T) {
	const clientId = "my-test-client"
	v, priv, issuer := newTestValidator(t, clientId)

	t.Run("withEmail", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"email": "user@example.com"})
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@example.com", user.Email)
		assert.Equal(t, "test-sub", user.Id)
		assert.Equal(t, "test-sub", user.Sub)
		assert.True(t, user.VerifiedEmail)
	})

	t.Run("fallsBackToPreferredUsername", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"preferred_username": "user@tenant.onmicrosoft.com"})
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@tenant.onmicrosoft.com", user.Email)
	})
}
