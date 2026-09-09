package guard

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// EnvRoles is the environment variable holding role assignments for
// EnvRoleStore. The value is one user per line, fields separated by ";":
//
//	alice@example.com;admin;user
//	bob@example.com;user
//
// Blank lines and lines starting with "#" are ignored.
const EnvRoles = "GUARD_ROLES"

// EnvRoleStore is a RoleStore read from the EnvRoles environment variable at
// construction. Roles resolve from config at startup rather than at mint time,
// so a restart picks up new assignments.
type EnvRoleStore struct {
	roles map[string][]string
}

// NewEnvRoleStore builds an EnvRoleStore from EnvRoles. It returns an error
// for any malformed line (missing ";", empty email, or a duplicate email) so
// configuration mistakes surface at startup instead of silently dropping
// assignments.
func NewEnvRoleStore() (*EnvRoleStore, error) {
	return newEnvRoleStoreFrom(os.Getenv(EnvRoles))
}

func newEnvRoleStoreFrom(raw string) (*EnvRoleStore, error) {
	roles := make(map[string][]string)
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s: line %d: want <email>;<role1>;<role2>;..., got %q", EnvRoles, i+1, line)
		}
		email := strings.TrimSpace(fields[0])
		if email == "" {
			return nil, fmt.Errorf("%s: line %d: missing email", EnvRoles, i+1)
		}
		if _, ok := roles[email]; ok {
			return nil, fmt.Errorf("%s: line %d: duplicate email %q", EnvRoles, i+1, email)
		}
		roles[email] = trimRoles(fields[1:])
	}
	return &EnvRoleStore{roles: roles}, nil
}

func trimRoles(fields []string) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (s *EnvRoleStore) RolesByEmail(_ context.Context, email string) ([]string, error) {
	return s.roles[email], nil
}
