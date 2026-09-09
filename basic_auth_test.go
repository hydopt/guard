package guard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIssuer = "https://auth.example.test"

// signWithExpiry issues a token with an explicit expiry, bypassing SignToken's
// clamping of non-positive TTLs so tests can exercise expiry handling.
func (v *Issuer) signWithExpiry(email string, exp time.Time, nonce string) (string, error) {
	claims := issuerClaims{
		Claims: jwt.Claims{
			Issuer:   v.issuer,
			Subject:  email,
			Expiry:   jwt.NewNumericDate(exp),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Email:         email,
		EmailVerified: true,
		Nonce:         nonce,
	}
	return jwt.Signed(v.signer).Claims(claims).Serialize()
}

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	v, err := NewIssuer(IssuerConfig{Issuer: testIssuer})
	require.NoError(t, err)
	return v
}

// mustIssuer returns an issuer configured for the given origin.
func mustIssuer(t *testing.T, issuer string) *Issuer {
	t.Helper()
	v, err := NewIssuer(IssuerConfig{Issuer: issuer})
	require.NoError(t, err)
	return v
}

func TestIssuerSignValidateRoundTrip(t *testing.T) {
	v := newTestIssuer(t)
	token, err := v.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)

	user, err := v.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "alice@example.com", user.Sub)
	assert.Equal(t, "alice@example.com", user.Id)
	assert.True(t, user.VerifiedEmail)
	assert.Equal(t, "alice@example.com", user.Claims["email"])
	assert.Equal(t, testIssuer, user.Claims["iss"])
}

func TestIssuerRolesFromStore(t *testing.T) {
	v, err := NewIssuer(IssuerConfig{
		Issuer: testIssuer,
		RoleStore: InMemoryRoleStore{
			"alice@example.com": {"admin", "editor"},
		},
	})
	require.NoError(t, err)

	token, err := v.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)
	user, err := v.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "editor"}, user.Roles)
	assert.Equal(t, []any{"admin", "editor"}, user.Claims["roles"])
}

func TestIssuerRolesOverride(t *testing.T) {
	v, err := NewIssuer(IssuerConfig{
		Issuer: testIssuer,
		RoleStore: InMemoryRoleStore{
			"alice@example.com": {"admin"},
		},
	})
	require.NoError(t, err)

	token, err := v.SignToken("alice@example.com", time.Hour, WithRoles([]string{"editor"}))
	require.NoError(t, err)
	user, err := v.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, []string{"editor"}, user.Roles)
}

func TestIssuerProviderAndCustomClaims(t *testing.T) {
	v := newTestIssuer(t)
	token, err := v.SignToken("alice@example.com", time.Hour,
		WithProvider("google"),
		WithClaim("tenant", "acme"),
	)
	require.NoError(t, err)

	user, err := v.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, "google", user.Provider)
	assert.Equal(t, "google", user.Claims["provider"])
	assert.Equal(t, "acme", user.Claims["tenant"])
}

func TestIssuerDownstreamPublicKeyValidation(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)

	// A downstream service validates with only the public key PEM.
	pemBytes, err := issuer.PublicKeyPEM()
	require.NoError(t, err)
	downstream, err := NewIssuer(IssuerConfig{
		PublicKeyPEM: pemBytes,
		Issuer:       testIssuer,
	})
	require.NoError(t, err)

	user, err := downstream.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)

	// The downstream issuer cannot sign.
	_, err = downstream.SignToken("bob@example.com", time.Hour)
	assert.ErrorIs(t, err, ErrNoPrivateKey)
}

func TestIssuerFromIssuerURL(t *testing.T) {
	// The issuer signs tokens whose iss equals the server origin, and serves
	// its own JWKS at that origin.
	var originIssuer *Issuer

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, JWKSPath, r.URL.Path)
		keyset, err := originIssuer.JWKS()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keyset)
	}))
	t.Cleanup(srv.Close)

	origin := strings.TrimSuffix(srv.URL, "/")
	originIssuer = mustIssuer(t, origin)
	token, err := originIssuer.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)

	// A real downstream discovers the keys from the origin and validates.
	downstream, err := NewValidatorFromIssuerURL(t.Context(), origin)
	require.NoError(t, err)
	assert.Equal(t, origin, downstream.IssuerURL())

	user, err := downstream.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
}

func TestIssuerFromIssuerURLNoKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{})
	}))
	t.Cleanup(srv.Close)

	_, err := NewValidatorFromIssuerURL(t.Context(), srv.URL)
	assert.ErrorIs(t, err, ErrNoIssuerFound)
}

func TestIssuerJWKS(t *testing.T) {
	v := newTestIssuer(t)
	keyset, err := v.JWKS()
	require.NoError(t, err)
	require.Len(t, keyset.Keys, 1)

	k := keyset.Keys[0]
	assert.Equal(t, "sig", k.Use)
	assert.Equal(t, "ES256", k.Algorithm)
	assert.Equal(t, v.KeyID(), k.KeyID)
	pub, ok := k.Key.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, v.publicKey, pub)

	// The JWKS key must be usable to verify a signed token.
	token, err := v.SignToken("bob@example.com", time.Hour)
	require.NoError(t, err)
	tk, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var claims issuerClaims
	require.NoError(t, tk.Claims(pub, &claims))
	assert.Equal(t, "bob@example.com", claims.Email)
}

func TestIssuerValidateRejects(t *testing.T) {
	v := newTestIssuer(t)

	t.Run("badSignature", func(t *testing.T) {
		other, err := NewIssuer(IssuerConfig{})
		require.NoError(t, err)
		token, err := other.SignToken("alice@example.com", time.Hour)
		require.NoError(t, err)
		_, err = v.ValidateToken(t.Context(), token)
		assert.Error(t, err)
	})

	t.Run("wrongIssuer", func(t *testing.T) {
		other, err := NewIssuer(IssuerConfig{Issuer: "https://evil.example.test"})
		require.NoError(t, err)
		token, err := other.SignToken("alice@example.com", time.Hour)
		require.NoError(t, err)
		_, err = v.ValidateToken(t.Context(), token)
		assert.Error(t, err)
	})

	t.Run("expired", func(t *testing.T) {
		token, err := v.signWithExpiry("alice@example.com", time.Now().Add(-time.Minute), "nonce")
		require.NoError(t, err)
		_, err = v.ValidateToken(t.Context(), token)
		assert.Error(t, err)
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := v.ValidateToken(t.Context(), "not.a.jwt")
		assert.Error(t, err)
	})
}

func TestIssuerKeyLifecycle(t *testing.T) {
	// Auto-generation round-trips through PEM.
	v := newTestIssuer(t)
	pemBytes, err := v.PublicKeyPEM()
	require.NoError(t, err)
	require.Contains(t, string(pemBytes), "PUBLIC KEY")

	// Parsing the exported PEM yields the same key.
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	pub, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.True(t, pub.Equal(v.publicKey))
}

func TestIssuerExplicitKeys(t *testing.T) {
	t.Run("privateKeyPEM", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalECPrivateKey(priv)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

		v, err := NewIssuer(IssuerConfig{PrivateKeyPEM: pemBytes, Issuer: testIssuer})
		require.NoError(t, err)
		token, err := v.SignToken("alice@example.com", time.Hour)
		require.NoError(t, err)
		user, err := v.ValidateToken(t.Context(), token)
		require.NoError(t, err)
		assert.Equal(t, "alice@example.com", user.Email)
	})

	t.Run("publicKeyPEMOnly", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

		v, err := NewIssuer(IssuerConfig{PublicKeyPEM: pemBytes})
		require.NoError(t, err)
		assert.Equal(t, "", v.IssuerURL())
		_, err = v.SignToken("alice@example.com", time.Hour)
		assert.ErrorIs(t, err, ErrNoPrivateKey)
	})

	t.Run("garbageKey", func(t *testing.T) {
		_, err := NewIssuer(IssuerConfig{PrivateKeyPEM: []byte("not pem")})
		assert.Error(t, err)
	})
}

func TestInMemoryRoleStore(t *testing.T) {
	store := InMemoryRoleStore{
		"alice@example.com": {"admin"},
	}
	roles, err := store.RolesByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, roles)

	// Unknown users resolve to no roles, not an error.
	roles, err = store.RolesByEmail(context.Background(), "carol@example.com")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestInMemoryCredentialStore(t *testing.T) {
	store := NewInMemoryCredentialStore(map[string]string{
		"alice@example.com": "s3cret",
	})

	t.Run("valid", func(t *testing.T) {
		require.NoError(t, store.Authenticate(context.Background(), "alice@example.com", "s3cret"))
	})

	t.Run("wrongPassword", func(t *testing.T) {
		assert.ErrorIs(t, store.Authenticate(context.Background(), "alice@example.com", "nope"), ErrUnauthorized)
	})

	t.Run("unknownEmail", func(t *testing.T) {
		assert.ErrorIs(t, store.Authenticate(context.Background(), "carol@example.com", "s3cret"), ErrUnauthorized)
	})

	t.Run("emptyPassword", func(t *testing.T) {
		assert.ErrorIs(t, store.Authenticate(context.Background(), "alice@example.com", ""), ErrUnauthorized)
	})
}

func TestIssuerValidateKeyIDMismatch(t *testing.T) {
	// A token whose header claims a different kid than the signing key must be
	// rejected. Rebuilding the header with a forged kid invalidates the
	// signature, so verification fails (the kid check alone would also catch it).
	v := newTestIssuer(t)
	token, err := v.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	hdrJSON := `{"alg":"ES256","kid":"forged","typ":"JWT"}`
	forged := base64.RawURLEncoding.EncodeToString([]byte(hdrJSON)) + "." + parts[1] + "." + parts[2]

	_, err = v.ValidateToken(t.Context(), forged)
	assert.Error(t, err)
}
