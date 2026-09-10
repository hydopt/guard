package guard

import "context"

// RoleStore resolves the roles for an email address. It is consulted when a
// guard session token is minted, so the resulting roles ride along as token
// claims. It is also used at request time by the EnrichFromStore middleware to
// refresh roles from the authoritative source.
type RoleStore interface {
	RolesByEmail(ctx context.Context, email string) ([]string, error)
}

// InMemoryRoleStore is a RoleStore backed by a static email-to-roles map.
type InMemoryRoleStore map[string][]string

func (s InMemoryRoleStore) RolesByEmail(_ context.Context, email string) ([]string, error) {
	return s[email], nil
}
