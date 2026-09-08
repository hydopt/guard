package components

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignInHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/signin", nil)
	rec := httptest.NewRecorder()

	SignInHandler([]Provider{
		{Name: "google", Label: "Google", StartPath: "/auth/google"},
		{Name: "microsoft", Label: "Microsoft", StartPath: "/auth/microsoft"},
	}).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `href="/auth/google"`)
	assert.Contains(t, body, "Continue with Google")
	assert.Contains(t, body, `href="/auth/microsoft"`)
	assert.Contains(t, body, "Continue with Microsoft")
}

func TestSignInHandler_NoProviders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/signin", nil)
	rec := httptest.NewRecorder()

	SignInHandler(nil).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "No sign-in providers configured.")
}
