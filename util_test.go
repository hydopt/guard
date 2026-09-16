package guard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/endpoint", nil)

	t.Run("no htmx request", func(t *testing.T) {
		rec := httptest.NewRecorder()
		Redirect(rec, req, "/other-endpoint", http.StatusFound)

		require.Equal(t, rec.Code, http.StatusFound)
	})

	req.Header.Set(HxRequest, "true")

	t.Run("htmx request", func(t *testing.T) {
		rec := httptest.NewRecorder()
		Redirect(rec, req, "/other-endpoint", http.StatusFound)

		require.Equal(t, rec.Code, http.StatusOK)

		require.Equal(t, rec.Header().Get(HxRedirect), "/other-endpoint")
	})
}
