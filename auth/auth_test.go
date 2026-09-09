package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hydopt/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/endpoints"
	googleoauth "golang.org/x/oauth2/google"
)

const testOrigin = "https://auth.example.test"

// fakeValidator accepts any token, letting Setup run without provider
// discovery or signatures.
type fakeValidator struct{}

func (fakeValidator) ValidateToken(_ context.Context, _ string) (*guard.User, error) {
	return &guard.User{Id: "user-1", Sub: "user-1", Email: "someone@example.com", VerifiedEmail: true}, nil
}

func newTestMux(t *testing.T, opts ...Option) (*http.ServeMux, *Auth) {
	t.Helper()
	mux := http.NewServeMux()
	a, err := Setup(mux, opts...)
	require.NoError(t, err)
	return mux, a
}

func TestSetupRegistersRoutes(t *testing.T) {
	mux, a := newTestMux(t,
		Issuer(testOrigin),
		Google("google-client"),
		Microsoft("microsoft-client"),
		WithValidator(googleProvider, fakeValidator{}),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	require.Len(t, a.Validators, 1, "by default only the guard issuer validates middleware requests")
	require.NotNil(t, a.Flow)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/signin", http.StatusOK},
		{http.MethodGet, "/auth/google", http.StatusFound},
		{http.MethodGet, "/auth/google/callback", http.StatusUnauthorized},
		{http.MethodGet, "/auth/microsoft", http.StatusFound},
		{http.MethodGet, "/auth/microsoft/callback", http.StatusUnauthorized},
		{http.MethodGet, "/auth/logout", http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, server.URL+tt.path, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, tt.status, resp.StatusCode, "%s %s", tt.method, tt.path)
	}
}

func TestSetupDefaults(t *testing.T) {
	_, a := newTestMux(t,
		Issuer(testOrigin),
		Google("google-client"),
		Microsoft("microsoft-client"),
		WithValidator(googleProvider, fakeValidator{}),
		WithValidator(microsoftProvider, fakeValidator{}),
	)

	flow := a.Flow
	assert.Equal(t, time.Hour, flow.SessionTTL())
	assert.False(t, flow.Secure())
	assert.Equal(t, "/", flow.HomePath())
	assert.Equal(t, "/signin", flow.SignInPath())
	assert.Equal(t, testOrigin, a.Issuer.IssuerURL())
	assert.Equal(t, testOrigin+guard.JWKSPath, a.JWKSURL)

	ms, ok := flow.Provider(microsoftProvider)
	require.True(t, ok)
	assert.Equal(t, endpoints.AzureAD(defaultTenant), ms.Endpoint)
	assert.Empty(t, ms.ClientSecret, "defaults to a public-client (PKCE) exchange")

	google, ok := flow.Provider(googleProvider)
	require.True(t, ok)
	assert.Equal(t, googleoauth.Endpoint, google.Endpoint)
}

func TestSetupMicrosoftTenant(t *testing.T) {
	_, a := newTestMux(t,
		Issuer(testOrigin),
		Microsoft("microsoft-client"),
		WithTenant("contoso.onmicrosoft.com"),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	ms, ok := a.Flow.Provider(microsoftProvider)
	require.True(t, ok)
	assert.Equal(t, endpoints.AzureAD("contoso.onmicrosoft.com"), ms.Endpoint)
}

func TestSetupRequiresIssuer(t *testing.T) {
	mux := http.NewServeMux()
	_, err := Setup(mux)
	assert.Error(t, err)
}

func TestSetupSecretsFromOptions(t *testing.T) {
	t.Setenv(EnvGoogleSecret, "env-secret")
	_, a := newTestMux(t,
		Issuer(testOrigin),
		Google("google-client"),
		WithGoogleSecret("option-secret"),
		WithValidator(googleProvider, fakeValidator{}),
	)
	google, ok := a.Flow.Provider(googleProvider)
	require.True(t, ok)
	assert.Equal(t, "option-secret", google.ClientSecret, "the explicit option must win over the env var")
}

func TestSetupSecretsFromEnv(t *testing.T) {
	t.Setenv(EnvGoogleSecret, "google-secret")
	t.Setenv(EnvMicrosoftSecret, "azure-secret")
	_, a := newTestMux(t,
		Issuer(testOrigin),
		Google("google-client"),
		Microsoft("microsoft-client"),
		WithValidator(googleProvider, fakeValidator{}),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	google, _ := a.Flow.Provider(googleProvider)
	assert.Equal(t, "google-secret", google.ClientSecret)
	ms, _ := a.Flow.Provider(microsoftProvider)
	assert.Equal(t, "azure-secret", ms.ClientSecret)
}

func TestSetupGoogleOnly(t *testing.T) {
	_, a := newTestMux(t,
		Issuer(testOrigin),
		Google("google-client"),
		WithValidator(googleProvider, fakeValidator{}),
	)
	require.Len(t, a.Validators, 1)
	_, ok := a.Flow.Provider(microsoftProvider)
	assert.False(t, ok)
}

func TestSetupMicrosoftOnly(t *testing.T) {
	_, a := newTestMux(t,
		Issuer(testOrigin),
		Microsoft("microsoft-client"),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	require.Len(t, a.Validators, 1)
	_, ok := a.Flow.Provider(googleProvider)
	assert.False(t, ok)
}

func TestSetupIssuerOnly(t *testing.T) {
	mux, a := newTestMux(t, Issuer("https://auth.example.test/"))
	require.NotNil(t, a.Issuer)
	require.Len(t, a.Validators, 1)
	assert.Equal(t, "https://auth.example.test", a.Issuer.IssuerURL())
	assert.Equal(t, "https://auth.example.test"+guard.JWKSPath, a.JWKSURL)

	// No login providers, so no sign-in flow is registered.
	assert.Nil(t, a.Flow)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	resp, err := http.Get(server.URL + guard.JWKSPath)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSetupEmailPassword(t *testing.T) {
	store := guard.NewInMemoryCredentialStore(map[string]string{"alice@example.com": "s3cret"})
	mux, a := newTestMux(t,
		Issuer(testOrigin),
		EmailPassword(store),
	)
	require.Len(t, a.Validators, 1)
	require.Equal(t, a.Issuer, a.Validators[0])
	require.NotNil(t, a.Flow)
	p, ok := a.Flow.Provider(basicAuthProvider)
	require.True(t, ok)
	assert.Equal(t, "Basic Auth", p.Label)
	assert.True(t, p.SignsSessionToken, "the email/password provider already mints guard tokens")

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// The login form is mounted at the authorize path with OAuth2 params.
	formURL := server.URL + p.Endpoint.AuthURL + "?client_id=basic-auth&response_type=code&redirect_uri=" +
		url.QueryEscape(server.URL+"/callback") + "&state=xyz&code_challenge=challenge&code_challenge_method=S256&nonce=nonce"
	resp, err := http.Get(formURL)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSetupEmailPasswordRequiresIssuer(t *testing.T) {
	// EmailPassword has no issuer to sign with, so Setup must reject it.
	mux := http.NewServeMux()
	_, err := Setup(mux, EmailPassword(guard.NewInMemoryCredentialStore(nil)))
	assert.Error(t, err)
}

func TestSetupEmailPasswordSoleProvider(t *testing.T) {
	mux := http.NewServeMux()
	a, err := Setup(mux, Issuer(testOrigin), EmailPassword(guard.NewInMemoryCredentialStore(nil)))
	require.NoError(t, err)
	require.NotNil(t, a.Flow)
	_, ok := a.Flow.Provider(basicAuthProvider)
	assert.True(t, ok)
}
