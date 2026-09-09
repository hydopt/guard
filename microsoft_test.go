package guard

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
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
		verifier: provider.Verifier(&oidc.Config{ClientID: clientId, SkipIssuerCheck: true}),
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

const testTenant = "11111111-2222-3333-4444-555555555555"
const otherTenant = "99999999-8888-7777-6666-555555555555"

func tenantIssuer(tenant string) string {
	return "https://login.microsoftonline.com/" + tenant + "/v2.0"
}

func TestNewMicrosoftTokenValidatorMultitenantModes(t *testing.T) {
	for _, tenant := range []string{msCommon, msOrganizations, msConsumers} {
		v, err := NewMicrosoftTokenValidator(tenant, "client-id")
		require.NoError(t, err, "tenant %q", tenant)
		require.Equal(t, "", v.pinnedTid, "tenant %q", tenant)
		require.NotNil(t, v.verifier)
	}
}

func TestNewMicrosoftTokenValidatorRequiresTenant(t *testing.T) {
	_, err := NewMicrosoftTokenValidator("", "client-id")
	assert.Error(t, err)
}

func TestValidateEntraTenantIssuer(t *testing.T) {
	issuer := tenantIssuer(testTenant)
	require.NoError(t, validateEntraTenantIssuer(issuer, testTenant))

	t.Run("mismatchedTenant", func(t *testing.T) {
		err := validateEntraTenantIssuer(tenantIssuer(otherTenant), testTenant)
		assert.ErrorContains(t, err, "does not match tenant")
	})

	t.Run("missingTid", func(t *testing.T) {
		assert.ErrorContains(t, validateEntraTenantIssuer(issuer, ""), "missing tid")
	})

	t.Run("nonGuidTid", func(t *testing.T) {
		assert.ErrorContains(t, validateEntraTenantIssuer("https://login.microsoftonline.com/demo/v2.0", "demo"), "not a GUID")
	})
}

func TestEntraTenantGUID(t *testing.T) {
	tid, ok := entraTenantGUID(tenantIssuer(testTenant))
	assert.True(t, ok)
	assert.Equal(t, testTenant, tid)

	tid, ok = entraTenantGUID(tenantIssuer(testTenant) + "/")
	assert.True(t, ok, "trailing slash tolerated")
	assert.Equal(t, testTenant, tid)

	for _, iss := range []string{
		"",
		"https://login.microsoftonline.com/{tenantid}/v2.0",
		"https://login.microsoftonline.com/demo/v2.0",
		"https://accounts.google.com",
		"https://login.microsoftonline.com/" + testTenant,
	} {
		_, ok := entraTenantGUID(iss)
		assert.False(t, ok, "issuer %q", iss)
	}
}

func TestResolvePinnedTid(t *testing.T) {
	t.Run("guidInput", func(t *testing.T) {
		tid, err := resolvePinnedTid(testTenant, "")
		require.NoError(t, err)
		assert.Equal(t, testTenant, tid)
	})

	t.Run("domainResolvedFromIssuer", func(t *testing.T) {
		tid, err := resolvePinnedTid("contoso.onmicrosoft.com", tenantIssuer(testTenant))
		require.NoError(t, err)
		assert.Equal(t, testTenant, tid)
	})

	t.Run("placeholderIssuer", func(t *testing.T) {
		_, err := resolvePinnedTid("contoso.onmicrosoft.com", "https://login.microsoftonline.com/{tenantid}/v2.0")
		assert.ErrorContains(t, err, "configure the tenant GUID")
	})
}

func TestFetchMicrosoftMetadata(t *testing.T) {
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   tenantIssuer(testTenant),
			"jwks_uri": serverURL + "/discovery/v2.0/keys",
		})
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL

	meta, err := fetchMicrosoftMetadata(t.Context(), serverURL)
	require.NoError(t, err)
	assert.Equal(t, tenantIssuer(testTenant), meta.Issuer)
	assert.NotEmpty(t, meta.JWKSURL)
}

func TestFetchMicrosoftMetadataErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	_, err := fetchMicrosoftMetadata(t.Context(), srv.URL)
	assert.Error(t, err)
}

func TestMicrosoftValidateToken(t *testing.T) {
	const clientId = "my-test-client"
	v, priv, _ := newTestValidator(t, clientId)
	issuer := tenantIssuer(testTenant)

	t.Run("withEmail", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"email": "user@example.com", "tid": testTenant})
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@example.com", user.Email)
		assert.Equal(t, "test-sub", user.Id)
		assert.Equal(t, "test-sub", user.Sub)
		assert.True(t, user.VerifiedEmail)
		assert.Equal(t, testTenant, user.Claims["tid"])
		assert.Equal(t, "user@example.com", user.Claims["email"])
	})

	t.Run("fallsBackToPreferredUsername", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"preferred_username": "user@tenant.onmicrosoft.com", "tid": testTenant})
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@tenant.onmicrosoft.com", user.Email)
	})

	t.Run("wrongTenant", func(t *testing.T) {
		token := signMicrosoftToken(t, tenantIssuer(otherTenant), clientId, priv, map[string]string{"email": "user@example.com", "tid": testTenant})
		_, err := v.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "does not match tenant")
	})

	t.Run("missingTid", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, clientId, priv, map[string]string{"email": "user@example.com"})
		_, err := v.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "missing tid")
	})

	t.Run("wrongAudience", func(t *testing.T) {
		token := signMicrosoftToken(t, issuer, "other-client", priv, map[string]string{"email": "user@example.com", "tid": testTenant})
		_, err := v.ValidateToken(t.Context(), token)
		assert.Error(t, err)
	})
}

func TestMicrosoftValidateTokenSingleTenantPinned(t *testing.T) {
	const clientId = "my-test-client"
	v, priv, _ := newTestValidator(t, clientId)
	v.pinnedTid = testTenant

	t.Run("validToken", func(t *testing.T) {
		token := signMicrosoftToken(t, tenantIssuer(testTenant), clientId, priv, map[string]string{"email": "user@example.com", "tid": testTenant})
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		assert.Equal(t, "user@example.com", user.Email)
	})

	t.Run("otherTenantRejected", func(t *testing.T) {
		token := signMicrosoftToken(t, tenantIssuer(otherTenant), clientId, priv, map[string]string{"email": "user@example.com", "tid": otherTenant})
		_, err := v.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "does not match configured tenant")
	})
}
