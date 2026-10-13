package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hydopt/guard"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	postgresImage    = "postgres:18-alpine"
	postgresUser     = "guard"
	postgresPassword = "guard"
	postgresDatabase = "guard"
)

// postgresDB starts a postgres container and returns a pool connected to it,
// both closed when the test ends.
func postgresDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	if testing.Short() {
		t.Skip("skipping postgres tests in short mode")
	}
	// The container needs a docker daemon; skip rather than fail without one.
	if provider, err := testcontainers.NewDockerProvider(); err != nil {
		t.Skipf("docker is unavailable, skipping postgres tests: %v", err)
	} else if err := provider.Close(); err != nil {
		t.Logf("closing the docker provider: %v", err)
	}

	container, err := postgres.Run(ctx, postgresImage,
		postgres.WithDatabase(postgresDatabase),
		postgres.WithUsername(postgresUser),
		postgres.WithPassword(postgresPassword),
		// The port opens before initdb finishes and the server restarts
		// afterwards, so wait for the second "ready" line rather than the port.
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(2*time.Minute)),
	)
	require.NoError(t, err, "start %s", postgresImage)
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container, testcontainers.StopContext(context.Background())); err != nil {
			t.Logf("terminating the postgres container: %v", err)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// tableSeq names the tables of each store, so the cases of the suite can share
// one container without sharing rows.
var tableSeq atomic.Int64

// newPostgresStore returns a migrated store with tables of its own. It goes
// through NewStore, so the dialect is detected from the driver rather than
// asked for.
func newPostgresStore(t *testing.T, db *sql.DB) *Store {
	t.Helper()

	n := tableSeq.Add(1)
	store := NewStore(db, fmt.Sprintf("users_%d", n), fmt.Sprintf("user_roles_%d", n))
	require.NoError(t, store.Migrate(t.Context()))
	return store
}

func TestStore_Postgres(t *testing.T) {
	db := postgresDB(t)
	// NewStore has to recognize pgx, or every query in the suite below runs
	// with ? bindings that postgres rejects.
	assert.Equal(t, DialectPostgres, detectDialect(db))
	storeSuite(t, func(t *testing.T) *Store { return newPostgresStore(t, db) })
}

// TestDetectDialect checks the driver-path matching behind the detection. The
// live path is covered by TestStore_Postgres, against a real pgx pool; lib/pq
// is matched here so the package needs no driver dependency to prove it.
func TestDetectDialect(t *testing.T) {
	for path, want := range map[string]Dialect{
		"github.com/jackc/pgx/v5/stdlib": DialectPostgres,
		"github.com/jackc/pgx/v4/stdlib": DialectPostgres,
		"github.com/lib/pq":              DialectPostgres,
		"modernc.org/sqlite":             DialectQuestionMark,
		"github.com/go-sql-driver/mysql": DialectQuestionMark,
	} {
		assert.Equal(t, want, dialectForDriverPath(path), path)
	}
}

// TestStore_PostgresExplicitDialect covers NewPostgresStore, which is how a
// caller whose driver hides its identity picks the dialect by hand.
func TestStore_PostgresExplicitDialect(t *testing.T) {
	db := postgresDB(t)
	ctx := t.Context()

	n := tableSeq.Add(1)
	usersTable := fmt.Sprintf("users_%d", n)
	store := NewPostgresStore(db, usersTable, fmt.Sprintf("user_roles_%d", n))
	require.NoError(t, store.Migrate(ctx))

	require.NoError(t, store.SetUser(ctx, "alice@example.com", "password", "admin", "user"))
	assert.NoError(t, store.Authenticate(ctx, "alice@example.com", "password"))
	assert.ErrorIs(t, store.Authenticate(ctx, "alice@example.com", "wrong-password"), guard.ErrUnauthorized)

	roles, err := store.RolesByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "user"}, roles)

	// The hashes sit in a BYTEA column, and the bcrypt round trip above already
	// showed the driver hands them back as bytes; check the column type too.
	var dataType string
	require.NoError(t, db.QueryRowContext(ctx,
		"SELECT data_type FROM information_schema.columns WHERE table_name = $1 AND column_name = 'password_hash'",
		usersTable).Scan(&dataType))
	assert.Equal(t, "bytea", dataType)
}
