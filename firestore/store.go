// Package firestore provides a Firestore-backed store for the guard
// interfaces: a single collection of user documents serves as both a
// guard.CredentialStore (bcrypt password hashes) and a guard.RoleStore, so one
// client and collection can back auth.EmailPassword and auth.WithRoleStore.
//
// The package is an optional, separately versioned module: importing it pulls
// in cloud.google.com/go/firestore, but the core github.com/hydopt/guard
// module stays free of cloud dependencies.
package firestore

import (
	"context"

	cloudfirestore "cloud.google.com/go/firestore"
	"github.com/hydopt/guard"
	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when a user document is missing, so an unknown
// email costs the same bcrypt work as a known one, blunting timing-based
// account enumeration.
var dummyHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("guard:missing-user"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}()

// Store is a guard.CredentialStore and guard.RoleStore backed by one Firestore
// collection. Each document is keyed by email and holds "password_hash" (a
// bcrypt hash, []byte) and "roles" ([]string).
type Store struct {
	client     *cloudfirestore.Client
	collection string
}

// NewStore returns a Store backed by collection.
func NewStore(client *cloudfirestore.Client, collection string) *Store {
	return &Store{client: client, collection: collection}
}

// Authenticate implements guard.CredentialStore. It loads the email's document
// and bcrypt-compares the password. Unknown emails run a dummy comparison
// before returning guard.ErrUnauthorized, so callers cannot tell an unknown
// user from a wrong password.
func (s *Store) Authenticate(ctx context.Context, email, password string) error {
	doc, err := s.client.Collection(s.collection).Doc(email).Get(ctx)
	if err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return guard.ErrUnauthorized
	}
	var rec struct {
		PasswordHash []byte `firestore:"password_hash"`
	}
	if err := doc.DataTo(&rec); err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return guard.ErrUnauthorized
	}
	if len(rec.PasswordHash) == 0 {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return guard.ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword(rec.PasswordHash, []byte(password)); err != nil {
		return guard.ErrUnauthorized
	}
	return nil
}

// RolesByEmail implements guard.RoleStore. A missing document means no roles.
func (s *Store) RolesByEmail(ctx context.Context, email string) ([]string, error) {
	doc, err := s.client.Collection(s.collection).Doc(email).Get(ctx)
	if err != nil {
		return nil, nil
	}
	var rec struct {
		Roles []string `firestore:"roles"`
	}
	if err := doc.DataTo(&rec); err != nil {
		return nil, nil
	}
	return rec.Roles, nil
}
