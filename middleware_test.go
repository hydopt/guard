package bearer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTokenValidator struct {
	user *User
	err  error
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (*User, error) {
	return m.user, m.err
}

type mockRoleStore struct {
	roles map[string]string
}

func (m *mockRoleStore) RoleByEmail(ctx context.Context, email string) (string, error) {
	if role, ok := m.roles[email]; ok {
		return role, nil
	}
	return "", nil
}

func TestChainOrder(t *testing.T) {
	var order []string

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m1")
			next.ServeHTTP(w, r)
		})
	}

	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "m2")
			next.ServeHTTP(w, r)
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		w.WriteHeader(http.StatusOK)
	})

	chain := Chain(m1, m2)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	chain(handler).ServeHTTP(rec, req)

	require.Equal(t, []string{"m1", "m2", "handler"}, order)
}

func TestRequireVerifiedEmailRejectsUnauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	validator := &mockTokenValidator{err: ErrUnauthorized}
	mw := RequireVerifiedEmail([]TokenValidator{validator})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireVerifiedEmailShortCircuits(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	validator := &mockTokenValidator{err: ErrUnauthorized}
	mw := RequireVerifiedEmail([]TokenValidator{validator})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	assert.False(t, called)
}

func TestRequireVerifiedEmailSetsUser(t *testing.T) {
	var gotUser *User
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = MustGetUserFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	user := &User{Email: "test@example.com"}
	validator := &mockTokenValidator{user: user}
	mw := RequireVerifiedEmail([]TokenValidator{validator})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.NotNil(t, gotUser)
	require.Equal(t, "test@example.com", gotUser.Email)
}

func TestRequireWhiteListedEmailRejects(t *testing.T) {
	user := &User{Email: "test@example.com"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	whitelist := []string{"other@example.com"}
	mw := Chain(
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := context.WithValue(r.Context(), userKey, user)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
		},
		RequireWhiteListedEmail(whitelist),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestOptionalAuthNoCredentials(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		user, ok := GetUserFromCtx(r.Context())
		assert.Nil(t, user)
		assert.False(t, ok)
		w.WriteHeader(http.StatusOK)
	})

	mw := OptionalAuth([]TokenValidator{&mockTokenValidator{err: ErrUnauthorized}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.True(t, called)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestOptionalAuthWithValidCredential(t *testing.T) {
	user := &User{Email: "test@example.com"}
	var gotToken string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := GetUserFromCtx(r.Context())
		require.True(t, ok)
		require.Equal(t, "test@example.com", got.Email)
		gotToken = MustGetTokenFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	mw := OptionalAuth([]TokenValidator{&mockTokenValidator{user: user}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "valid-token", gotToken)
}

func TestOptionalAuthInvalidCredentialPassesThrough(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, ok := GetUserFromCtx(r.Context())
		assert.False(t, ok)
		w.WriteHeader(http.StatusOK)
	})

	mw := OptionalAuth([]TokenValidator{&mockTokenValidator{err: ErrUnauthorized}})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.True(t, called)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestChainWithAuthAndWhitelist(t *testing.T) {
	user := &User{Email: "admin@example.com"}
	validator := &mockTokenValidator{user: user}
	whitelist := []string{"admin@example.com"}

	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := Chain(
		RequireVerifiedEmail([]TokenValidator{validator}),
		RequireWhiteListedEmail(whitelist),
	)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called)
}
