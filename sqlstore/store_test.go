package sqlstore

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/hydopt/guard"
	"github.com/hydopt/guard/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	// An in-memory SQLite database lives per connection, so keep the pool to a
	// single connection or the schema becomes invisible to other connections.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	store := NewStore(db, "users", "user_roles")
	require.NoError(t, store.Migrate(t.Context()))
	return store
}

func TestStore_Authenticate(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	require.NoError(t, s.SetUser(ctx, "alice@example.com", "password", "admin", "user"))

	assert.NoError(t, s.Authenticate(ctx, "alice@example.com", "password"))
	assert.ErrorIs(t, s.Authenticate(ctx, "alice@example.com", "wrong-password"), guard.ErrUnauthorized)
	assert.ErrorIs(t, s.Authenticate(ctx, "unknown@example.com", "password"), guard.ErrUnauthorized)
}

func TestStore_RolesByEmail(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	require.NoError(t, s.SetUser(ctx, "alice@example.com", "password", "admin", "user"))

	roles, err := s.RolesByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "user"}, roles)

	roles, err = s.RolesByEmail(ctx, "unknown@example.com")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestStore_SetUserReplacesRoles(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()

	require.NoError(t, s.SetUser(ctx, "alice@example.com", "first", "admin", "user"))
	require.NoError(t, s.SetUser(ctx, "alice@example.com", "second", "editor"))

	assert.NoError(t, s.Authenticate(ctx, "alice@example.com", "second"))
	assert.ErrorIs(t, s.Authenticate(ctx, "alice@example.com", "first"), guard.ErrUnauthorized)

	roles, err := s.RolesByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"editor"}, roles)
}

func TestStore_ImplementsInterfaces(t *testing.T) {
	s := &Store{}
	var _ guard.CredentialStore = s
	var _ guard.RoleStore = s
}

func TestStore_AuthSetupEndToEnd(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.SetUser(t.Context(), "alice@example.com", "password", "admin", "user"))

	mux := http.NewServeMux()
	a, err := auth.Setup(mux,
		auth.Issuer("https://auth.example.test"),
		auth.EmailPassword(s),
		auth.WithRoleStore(s),
	)
	require.NoError(t, err)

	token, err := a.Issuer.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)
	user, err := a.Issuer.ValidateToken(t.Context(), token)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, []string{"admin", "user"}, user.Roles)
}
