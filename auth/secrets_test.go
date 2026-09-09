package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSecretValueOrPath(t *testing.T) {
	t.Run("literalValue", func(t *testing.T) {
		t.Setenv("GUARD_TEST_SECRET", "s3cret")
		v, err := LoadSecret("GUARD_TEST_SECRET")
		require.NoError(t, err)
		assert.Equal(t, "s3cret", v)
	})

	t.Run("filePath", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret")
		require.NoError(t, os.WriteFile(path, []byte("from-file\n"), 0o600))
		t.Setenv("GUARD_TEST_SECRET", path)
		v, err := LoadSecret("GUARD_TEST_SECRET")
		require.NoError(t, err)
		assert.Equal(t, "from-file", v, "file secrets are read and trimmed")
	})

	t.Run("missing", func(t *testing.T) {
		_, err := LoadSecret("GUARD_TEST_UNSET_VARIABLE")
		assert.ErrorIs(t, err, ErrEnvMissing)
	})

	t.Run("unreadableFileFails", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
		require.NoError(t, os.Chmod(path, 0o000))
		t.Setenv("GUARD_TEST_SECRET", path)
		_, err := LoadSecret("GUARD_TEST_SECRET")
		assert.Error(t, err)
	})

	t.Run("pathToDirectoryTreatedAsLiteral", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GUARD_TEST_SECRET", dir)
		v, err := LoadSecret("GUARD_TEST_SECRET")
		require.NoError(t, err)
		assert.Equal(t, dir, v)
	})
}

func TestLoadSecretBytes(t *testing.T) {
	b, err := LoadSecretBytes("GUARD_TEST_UNSET_VARIABLE_TOO")
	require.ErrorIs(t, err, ErrEnvMissing)
	assert.Nil(t, b)

	t.Setenv("GUARD_TEST_SECRET", "-----BEGIN EC PRIVATE KEY-----\n")
	b, err = LoadSecretBytes("GUARD_TEST_SECRET")
	require.NoError(t, err)
	assert.Equal(t, "-----BEGIN EC PRIVATE KEY-----\n", string(b))
}
