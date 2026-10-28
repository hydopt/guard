package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hydopt/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rejectingValidator struct{}

func (rejectingValidator) ValidateToken(_ context.Context, _ string) (*guard.User, error) {
	return nil, errors.New("invalid token")
}

func TestTokenExchange(t *testing.T) {
	mux := http.NewServeMux()
	a, err := Setup(mux,
		Issuer(testOrigin),
		GoogleDesktop("desktop-client"),
		WithValidator(googleProvider, fakeValidator{}),
		WithRoleStore(guard.InMemoryRoleStore{"someone@example.com": {"admin"}}),
	)
	require.NoError(t, err)
	require.Nil(t, a.Flow, "the desktop audience alone does not add a browser provider")
	assert.Equal(t, []string{guard.TokenExchangePath}, a.PublicRoutes())

	// The exchange must stay reachable even when the app protects everything
	// with RequireLogin (issuer-only mode here).
	server := httptest.NewServer(a.RequireLogin()(mux))
	t.Cleanup(server.Close)

	resp := postExchange(t, server.URL, url.Values{
		"provider": {"google"},
		"id_token": {"google-id-token"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	defer resp.Body.Close()

	var payload struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, "Bearer", payload.TokenType)
	assert.Equal(t, 3600, payload.ExpiresIn)

	user, err := a.Issuer.ValidateToken(context.Background(), payload.Token)
	require.NoError(t, err)
	assert.Equal(t, "someone@example.com", user.Email)
	assert.Equal(t, "google", user.Provider)
	assert.Equal(t, []string{"admin"}, user.Roles)
}

func TestTokenExchangeRejects(t *testing.T) {
	mux := http.NewServeMux()
	_, err := Setup(mux,
		Issuer(testOrigin),
		Google("google-client"),
		WithValidator(googleProvider, rejectingValidator{}),
	)
	require.NoError(t, err)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	tests := []struct {
		name   string
		method string
		form   url.Values
		status int
	}{
		{"method", http.MethodGet, nil, http.StatusMethodNotAllowed},
		{"missingProvider", http.MethodPost, url.Values{"id_token": {"x"}}, http.StatusBadRequest},
		{"missingToken", http.MethodPost, url.Values{"provider": {"google"}}, http.StatusBadRequest},
		{"unknownProvider", http.MethodPost, url.Values{"provider": {"nope"}, "id_token": {"x"}}, http.StatusBadRequest},
		{"invalidToken", http.MethodPost, url.Values{"provider": {"google"}, "id_token": {"x"}}, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.NewReader(tt.form.Encode())
			req, err := http.NewRequest(tt.method, server.URL+guard.TokenExchangePath, body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, tt.status, resp.StatusCode)
		})
	}
}

func postExchange(t *testing.T, baseURL string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+guard.TokenExchangePath, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}
