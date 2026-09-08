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

func newGoogleOidcServer(t *testing.T) (*oidctest.Server, *rsa.PrivateKey, string) {
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
	return s, priv, srv.URL
}

func signGoogleToken(t *testing.T, issuer, clientId string, priv *rsa.PrivateKey, email string, verified bool) string {
	t.Helper()
	claimsJSON := `{
		"iss": "` + issuer + `",
		"aud": "` + clientId + `",
		"sub": "test-sub",
		"email": "` + email + `",
		"email_verified": ` + strconv.FormatBool(verified) + `,
		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `
	}`
	return oidctest.SignIDToken(priv, testKeyID, "RS256", claimsJSON)
}

func TestGoogleValidateToken(t *testing.T) {
	const clientId = "my-test-client"
	_, priv, issuer := newGoogleOidcServer(t)

	provider, err := oidc.NewProvider(t.Context(), issuer)
	require.NoError(t, err)
	g := &GoogleTokenValidator{
		ClientId: clientId,
		verifier: provider.Verifier(&oidc.Config{ClientID: clientId}),
		fallback: provider.Verifier(&oidc.Config{ClientID: clientId}),
	}

	t.Run("validToken", func(t *testing.T) {
		token := signGoogleToken(t, issuer, clientId, priv, "user@example.com", true)
		user, err := g.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "user@example.com", user.Email)
		assert.Equal(t, "test-sub", user.Id)
		assert.Equal(t, "test-sub", user.Sub)
		assert.True(t, user.VerifiedEmail)
	})

	t.Run("wrongAudience", func(t *testing.T) {
		token := signGoogleToken(t, issuer, "other-client", priv, "user@example.com", true)
		_, err := g.ValidateToken(t.Context(), token)
		assert.Error(t, err)
	})

	t.Run("unverifiedEmail", func(t *testing.T) {
		token := signGoogleToken(t, issuer, clientId, priv, "user@example.com", false)
		_, err := g.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "email is not verified")
	})

	t.Run("missingEmail", func(t *testing.T) {
		token := signGoogleToken(t, issuer, clientId, priv, "", true)
		_, err := g.ValidateToken(t.Context(), token)
		assert.ErrorContains(t, err, "missing email")
	})
}

func TestGoogleValidateTokenFallbackIssuer(t *testing.T) {
	const clientId = "my-test-client"
	_, _, issuerA := newGoogleOidcServer(t)
	_, privB, issuerB := newGoogleOidcServer(t)

	providerA, err := oidc.NewProvider(t.Context(), issuerA)
	require.NoError(t, err)
	providerB, err := oidc.NewProvider(t.Context(), issuerB)
	require.NoError(t, err)

	g := &GoogleTokenValidator{
		ClientId: clientId,
		verifier: providerA.Verifier(&oidc.Config{ClientID: clientId}),
		fallback: providerB.Verifier(&oidc.Config{ClientID: clientId}),
	}

	// Token from issuer B: the primary verifier (issuer A) rejects it, the
	// fallback verifier (mirroring the legacy "accounts.google.com" keyset)
	// accepts it.
	token := signGoogleToken(t, issuerB, clientId, privB, "user@example.com", true)
	user, err := g.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "user@example.com", user.Email)
}
