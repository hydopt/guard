package guard

import (
	"context"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// ErrUnauthorized is the canonical error for failed credential checks. It is
// defined in validate.go and reused here so callers can compare with it.
var ErrInvalidCredentials = ErrUnauthorized

// CredentialStore authenticates a user by email and password. It is consumed
// by the basic-auth login flow to verify a user before a token is issued.
type CredentialStore interface {
	// Authenticate validates the email/password combination. It returns nil on
	// success and an error otherwise. Implementations should avoid distinguishing
	// an unknown email from a wrong password to prevent account enumeration.
	Authenticate(ctx context.Context, email, password string) error
}

// InMemoryCredentialStore is a CredentialStore backed by a static map of
// email to plaintext password. Passwords are accepted in plaintext and
// immediately bcrypt-hashed; the plaintext is never retained.
type InMemoryCredentialStore struct {
	mu    sync.RWMutex
	users map[string][]byte // email -> bcrypt hash
}

// NewInMemoryCredentialStore builds a store from an email->password map. The
// plaintext passwords are hashed here and discarded.
func NewInMemoryCredentialStore(users map[string]string) *InMemoryCredentialStore {
	hashed := make(map[string][]byte, len(users))
	for email, password := range users {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			// bcrypt never fails for valid input; keep the entry unusable as a
			// safety net rather than drop it silently.
			h = nil
		}
		hashed[email] = h
	}
	return &InMemoryCredentialStore{users: hashed}
}

// Authenticate reports whether email and password match a stored user. It
// returns ErrUnauthorized both for unknown emails and wrong passwords, so
// callers cannot enumerate accounts.
func (s *InMemoryCredentialStore) Authenticate(_ context.Context, email, password string) error {
	s.mu.RLock()
	hash, ok := s.users[email]
	s.mu.RUnlock()
	if !ok || hash == nil {
		return ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return ErrUnauthorized
	}
	return nil
}
