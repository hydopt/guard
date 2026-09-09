package guard

import "context"

// RoleStore resolves the roles for an email address. It is consulted when a
// guard session token is minted, so the resulting roles ride along as token
// claims and downstream services can authorize without contacting the store.
type RoleStore interface {
	RolesByEmail(ctx context.Context, email string) ([]string, error)
}

// InMemoryRoleStore is a RoleStore backed by a static email-to-roles map.
type InMemoryRoleStore map[string][]string

func (s InMemoryRoleStore) RolesByEmail(_ context.Context, email string) ([]string, error) {
	return s[email], nil
}
