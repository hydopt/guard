package auth

import (
	"errors"
	"os"
	"strings"
)

// ErrEnvMissing is returned by LoadSecret when the environment variable is not
// set. Use errors.Is to distinguish a missing optional secret from a file read
// error.
var ErrEnvMissing = errors.New("auth: environment variable is not set")

// LoadSecret resolves an environment variable whose value is either the secret
// itself or the path of a file holding it (a common pattern on cloud and
// docker-compose deployments that mount secrets as files). An unset variable
// returns ErrEnvMissing. A value that names an existing regular file is read
// and trimmed of surrounding whitespace; any other value is returned verbatim.
func LoadSecret(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", ErrEnvMissing
	}
	if contents, ok, err := readSecretFile(value); err != nil {
		return "", err
	} else if ok {
		return contents, nil
	}
	return value, nil
}

// LoadSecretBytes is LoadSecret for binary secrets such as PEM-encoded keys.
func LoadSecretBytes(name string) ([]byte, error) {
	s, err := LoadSecret(name)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// readSecretFile loads value as a file when it names an existing regular file.
func readSecretFile(value string) (contents string, ok bool, err error) {
	info, err := os.Stat(value)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if info.IsDir() {
		return "", false, nil
	}
	b, err := os.ReadFile(value)
	if err != nil {
		return "", false, err
	}
	return strings.TrimSpace(string(b)), true, nil
}
