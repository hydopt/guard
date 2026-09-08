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

func TestSignInHandler_ForwardsNext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/signin?next=/private%3Ftab%3D2", nil)
	rec := httptest.NewRecorder()

	SignInHandler([]Provider{
		{Name: "google", Label: "Google", StartPath: "/auth/google"},
	}).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `href="/auth/google?next=%2Fprivate%3Ftab%3D2"`)
}

func TestSignInHandler_DropsUnsafeNext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/signin?next=https://evil.com", nil)
	rec := httptest.NewRecorder()

	SignInHandler([]Provider{
		{Name: "google", Label: "Google", StartPath: "/auth/google"},
	}).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, `href="/auth/google"`)
	assert.NotContains(t, body, "evil.com")
	assert.NotContains(t, body, "next=")
}
