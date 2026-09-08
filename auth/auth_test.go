package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hydopt/bearer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/endpoints"
	googleoauth "golang.org/x/oauth2/google"
)

// fakeValidator accepts any token, letting Setup run without provider
// discovery or signatures.
type fakeValidator struct{}

func (fakeValidator) ValidateToken(_ context.Context, _ string) (*bearer.User, error) {
	return &bearer.User{Id: "user-1", Sub: "user-1", Email: "someone@example.com", VerifiedEmail: true}, nil
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
		Google("google-client"),
		Microsoft("microsoft-client"),
		WithValidator(googleProvider, fakeValidator{}),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	require.Len(t, a.Validators, 2)
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
		Microsoft("microsoft-client"),
		WithTenant("contoso.onmicrosoft.com"),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	ms, ok := a.Flow.Provider(microsoftProvider)
	require.True(t, ok)
	assert.Equal(t, endpoints.AzureAD("contoso.onmicrosoft.com"), ms.Endpoint)
}

func TestSetupRequiresProvider(t *testing.T) {
	mux := http.NewServeMux()
	_, err := Setup(mux)
	assert.Error(t, err)
}

func TestSetupSecretsFromOptions(t *testing.T) {
	t.Setenv(EnvGoogleSecret, "env-secret")
	_, a := newTestMux(t,
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
		Google("google-client"),
		WithValidator(googleProvider, fakeValidator{}),
	)
	require.Len(t, a.Validators, 1)
	_, ok := a.Flow.Provider(microsoftProvider)
	assert.False(t, ok)
}

func TestSetupMicrosoftOnly(t *testing.T) {
	_, a := newTestMux(t,
		Microsoft("microsoft-client"),
		WithValidator(microsoftProvider, fakeValidator{}),
	)
	require.Len(t, a.Validators, 1)
	_, ok := a.Flow.Provider(googleProvider)
	assert.False(t, ok)
}
