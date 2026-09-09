package guard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnvRoleStoreFrom(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    map[string][]string
		wantErr string
	}{
		{
			name: "empty",
			raw:  "",
			want: map[string][]string{},
		},
		{
			name: "blank and comment lines only",
			raw:  "\n  \n# comment\n#another",
			want: map[string][]string{},
		},
		{
			name: "multiple users",
			raw:  "alice@example.com;admin;user\nbob@example.com;user",
			want: map[string][]string{
				"alice@example.com": {"admin", "user"},
				"bob@example.com":   {"user"},
			},
		},
		{
			name: "fields are trimmed",
			raw:  " alice@example.com ; admin ; user \nbob@example.com;\n",
			want: map[string][]string{
				"alice@example.com": {"admin", "user"},
				"bob@example.com":   {},
			},
		},
		{
			name: "empty roles allowed",
			raw:  "alice@example.com;",
			want: map[string][]string{
				"alice@example.com": {},
			},
		},
		{
			name:    "no semicolon",
			raw:     "alice@example.com",
			wantErr: "want <email>;<role1>;<role2>;...",
		},
		{
			name:    "missing email",
			raw:     ";admin",
			wantErr: "missing email",
		},
		{
			name:    "duplicate email",
			raw:     "alice@example.com;user\nalice@example.com;admin",
			wantErr: "duplicate email",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := newEnvRoleStoreFrom(tt.raw)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, store.roles)
		})
	}
}

func TestNewEnvRoleStore(t *testing.T) {
	t.Setenv(EnvRoles, "alice@example.com;admin;user\n# bob is commented out\nbob@example.com;user")
	store, err := NewEnvRoleStore()
	require.NoError(t, err)

	roles, err := store.RolesByEmail(t.Context(), "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin", "user"}, roles)

	roles, err = store.RolesByEmail(t.Context(), "bob@example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"user"}, roles)

	roles, err = store.RolesByEmail(t.Context(), "unknown@example.com")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestNewEnvRoleStoreUnset(t *testing.T) {
	t.Setenv(EnvRoles, "")
	store, err := NewEnvRoleStore()
	require.NoError(t, err)
	roles, err := store.RolesByEmail(t.Context(), "alice@example.com")
	require.NoError(t, err)
	assert.Empty(t, roles)
}
