package sqlstore

import (
	"database/sql"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/hydopt/guard"
	"github.com/hydopt/guard/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func newSQLiteStore(t *testing.T) *Store {
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

func TestStore_SQLite(t *testing.T) {
	storeSuite(t, newSQLiteStore)
}

// storeSuite runs the behaviors every supported driver must show. Each case
// builds its own store, so cases never share rows.
func storeSuite(t *testing.T, newStore func(*testing.T) *Store) {
	t.Helper()

	t.Run("Authenticate", func(t *testing.T) {
		s := newStore(t)
		ctx := t.Context()

		require.NoError(t, s.SetUser(ctx, "alice@example.com", "password", "admin", "user"))

		assert.NoError(t, s.Authenticate(ctx, "alice@example.com", "password"))
		assert.ErrorIs(t, s.Authenticate(ctx, "alice@example.com", "wrong-password"), guard.ErrUnauthorized)
		assert.ErrorIs(t, s.Authenticate(ctx, "unknown@example.com", "password"), guard.ErrUnauthorized)
	})

	t.Run("RolesByEmail", func(t *testing.T) {
		s := newStore(t)
		ctx := t.Context()

		require.NoError(t, s.SetUser(ctx, "alice@example.com", "password", "admin", "user"))

		roles, err := s.RolesByEmail(ctx, "alice@example.com")
		require.NoError(t, err)
		assert.Equal(t, []string{"admin", "user"}, roles)

		roles, err = s.RolesByEmail(ctx, "unknown@example.com")
		require.NoError(t, err)
		assert.Empty(t, roles)
	})

	t.Run("SetUserReplacesRoles", func(t *testing.T) {
		s := newStore(t)
		ctx := t.Context()

		require.NoError(t, s.SetUser(ctx, "alice@example.com", "first", "admin", "user"))
		require.NoError(t, s.SetUser(ctx, "alice@example.com", "second", "editor"))

		assert.NoError(t, s.Authenticate(ctx, "alice@example.com", "second"))
		assert.ErrorIs(t, s.Authenticate(ctx, "alice@example.com", "first"), guard.ErrUnauthorized)

		roles, err := s.RolesByEmail(ctx, "alice@example.com")
		require.NoError(t, err)
		assert.Equal(t, []string{"editor"}, roles)
	})

	t.Run("AuthSetupEndToEnd", func(t *testing.T) {
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
	})

	t.Run("Roles", func(t *testing.T) {
		s := newStore(t)
		ctx := t.Context()
		require.NoError(t, s.SetUser(ctx, "alice@example.com", "first", "admin", "user"))
		roles, err := s.Roles(ctx)
		require.NoError(t, err)
		require.Len(t, roles, 1)
		aliceRoles := roles["alice@example.com"]
		slices.Sort(aliceRoles)
		require.Equal(t, []string{"admin", "user"}, aliceRoles)
	})
}

func TestStore_ImplementsInterfaces(t *testing.T) {
	s := &Store{}
	var _ guard.CredentialStore = s
	var _ guard.RoleStore = s
}

func TestRebind(t *testing.T) {
	questionMarks := "SELECT role FROM user_roles WHERE email = ? ORDER BY role"
	assert.Equal(t, questionMarks, rebind(questionMarks, DialectQuestionMark))

	assert.Equal(t,
		"SELECT role FROM user_roles WHERE email = $1 ORDER BY role",
		rebind(questionMarks, DialectPostgres))

	// Numbering follows the placeholders, not the characters around them, and
	// literals are left alone so a '?' inside one is not rewritten.
	assert.Equal(t,
		"SELECT email, role FROM user_roles WHERE role <> '? maybe' AND role <> $1 AND email = $2",
		rebind("SELECT email, role FROM user_roles WHERE role <> '? maybe' AND role <> ? AND email = ?", DialectPostgres))
}
