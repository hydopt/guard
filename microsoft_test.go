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
