package guard

import (
	"context"
	"errors"
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

// withUser injects a user into the request context, standing in for
// RequireVerifiedEmail further up the chain.
func withUser(user *User) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), userKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireVerifiedEmailRejectsNonBearerScheme(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	mw := RequireVerifiedEmail([]TokenValidator{&mockTokenValidator{user: &User{Email: "test@example.com"}}})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestRequireAnyRoleAllows(t *testing.T) {
	admin := &User{Email: "admin@example.com", Roles: []string{"editor", "admin"}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	mw := Chain(withUser(admin), RequireAnyRole("viewer", "admin"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAnyRoleRejectsForbidden(t *testing.T) {
	user := &User{Email: "user@example.com", Roles: []string{"viewer"}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	mw := Chain(withUser(user), RequireAnyRole("admin", "owner"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequireAllRolesAllows(t *testing.T) {
	user := &User{Email: "user@example.com", Roles: []string{"admin", "editor"}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	mw := Chain(withUser(user), RequireAllRoles("admin", "editor"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestRequireAllRolesRejectsMissing(t *testing.T) {
	user := &User{Email: "user@example.com", Roles: []string{"admin"}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	mw := Chain(withUser(user), RequireAllRoles("admin", "editor"))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code)
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

type errRoleStore struct{ err error }

func (e errRoleStore) RolesByEmail(_ context.Context, _ string) ([]string, error) {
	return nil, e.err
}

func TestEnrichFromStoreOverwritesRoles(t *testing.T) {
	user := &User{Email: "alice@example.com", Roles: []string{"stale"}}
	store := InMemoryRoleStore{"alice@example.com": {"admin", "editor"}}

	var gotRoles []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRoles = MustGetUserFromCtx(r.Context()).Roles
		w.WriteHeader(http.StatusOK)
	})

	mw := Chain(withUser(user), EnrichFromStore(store))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, []string{"admin", "editor"}, gotRoles)
}

func TestEnrichFromStoreClearsOnStoreError(t *testing.T) {
	user := &User{Email: "alice@example.com", Roles: []string{"admin"}}
	store := errRoleStore{err: errors.New("database down")}

	var gotRoles []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRoles = MustGetUserFromCtx(r.Context()).Roles
		w.WriteHeader(http.StatusOK)
	})

	mw := Chain(withUser(user), EnrichFromStore(store))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, gotRoles)
}

func TestEnrichFromStoreEmptyResult(t *testing.T) {
	user := &User{Email: "alice@example.com", Roles: []string{"admin"}}
	store := InMemoryRoleStore{}

	var gotRoles []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRoles = MustGetUserFromCtx(r.Context()).Roles
		w.WriteHeader(http.StatusOK)
	})

	mw := Chain(withUser(user), EnrichFromStore(store))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Empty(t, gotRoles)
}
