package firestore

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	cloudfirestore "cloud.google.com/go/firestore"
	"github.com/hydopt/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST not set; run with the Firestore emulator to exercise this test")
	}
	ctx := context.Background()
	client, err := cloudfirestore.NewClient(ctx, "test-project")
	require.NoError(t, err, "connect to the Firestore emulator")
	collection := "guard_test_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	return &Store{client: client, collection: collection}
}

func TestStore_AuthenticateAndRoles(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	require.NoError(t, err)
	_, err = s.client.Collection(s.collection).Doc("alice@example.com").Set(ctx, map[string]any{
		"password_hash": hash,
		"roles":         []string{"admin", "user"},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = s.client.Collection(s.collection).Doc("alice@example.com").Delete(context.Background())
	})

	assert.NoError(t, s.Authenticate(ctx, "alice@example.com", "password"))
	assert.ErrorIs(t, s.Authenticate(ctx, "alice@example.com", "wrong-password"), guard.ErrUnauthorized)
	assert.ErrorIs(t, s.Authenticate(ctx, "unknown@example.com", "password"), guard.ErrUnauthorized)

	roles, err := s.RolesByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "user"}, roles)

	roles, err = s.RolesByEmail(ctx, "unknown@example.com")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestStore_ImplementsInterfaces(t *testing.T) {
	s := &Store{}
	var _ guard.CredentialStore = s
	var _ guard.RoleStore = s
}
