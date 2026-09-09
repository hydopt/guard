// Package auth wires the sign-in flow and the guard token issuer into a
// http.ServeMux with sensible defaults, so a typical app needs a few calls
// instead of assembling providers and endpoints by hand.
package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hydopt/guard"
	"github.com/hydopt/guard/signin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	googleoauth "golang.org/x/oauth2/google"
)

const (
	googleProvider       = "google"
	microsoftProvider    = "microsoft"
	basicAuthProvider    = "basic-auth"
	basicAuthClientID    = "basic-auth"
	basicAuthClientLabel = "Basic Auth"
	defaultTenant        = "common"
)

// Env vars consulted for the confidential-client secrets when no explicit
// option is given. Leave unset for public clients, where PKCE alone protects
// the code exchange.
const (
	EnvGoogleSecret    = "GOOGLE_CLIENT_SECRET"
	EnvMicrosoftSecret = "AZURE_CLIENT_SECRET"
)

// Auth is what Setup returns: the guard issuer, the registered sign-in flow,
// and the middleware validators ready to feed the auth middlewares.
type Auth struct {
	Flow   *signin.Flow
	Issuer *guard.Issuer
	// Validators for the auth middlewares. By default only the guard issuer
	// itself, so Bearer tokens must be guard tokens. Google/Microsoft tokens
	// are only accepted at the sign-in boundary.
	Validators []guard.TokenValidator
	// JWKSURL is the absolute discovery URL for the guard signing keys.
	JWKSURL string
}

// Option configures Setup.
type Option func(*config)

type config struct {
	googleClientID     string
	microsoftClientID  string
	googleSecret       string
	microsoftSecret    string
	tenant             string
	secure             bool
	sessionTTL         time.Duration
	validators         map[string]guard.TokenValidator
	issuerOrigin       string
	sessionKey         []byte
	roleStore          guard.RoleStore
	emailPasswordStore guard.CredentialStore
}

// Google enables the Google sign-in provider for the given OAuth client ID.
// Its tokens are valid at the sign-in boundary only; the issued guard token is
// what downstream services accept.
func Google(clientID string) Option {
	return func(c *config) { c.googleClientID = clientID }
}

// Microsoft enables the Microsoft Entra ID sign-in provider for the given
// OAuth client ID. Uses the multi-tenant "common" audience unless overridden
// with WithTenant. Its tokens are valid at the sign-in boundary only.
func Microsoft(clientID string) Option {
	return func(c *config) { c.microsoftClientID = clientID }
}

// Issuer is required. It sets the self-hosted guard issuer origin: every
// signed-in user gets a guard token whose iss claim is origin, and the signing
// keys are served at {origin}/.well-known/jwks.json so downstream services can
// discover and validate them by fetching that URL.
//
// Without WithSessionKey the app generates an ECDSA P-256 key pair in memory,
// which resets on restart (invalidating outstanding sessions). Configure a
// stable key in production.
func Issuer(origin string) Option {
	return func(c *config) { c.issuerOrigin = strings.TrimRight(origin, "/") }
}

// WithSessionKey supplies the PEM-encoded ECDSA P-256 private key the issuer
// signs guard tokens with. Without it, an ephemeral in-memory key is generated
// and sessions reset on restart. Reading from a file or environment at startup:
//
//	WithSessionKey(pemBytes)
func WithSessionKey(pemBytes []byte) Option {
	return func(c *config) { c.sessionKey = pemBytes }
}

// WithRoleStore supplies the role store the issuer consults when minting guard
// tokens, so downstream services receive the user's roles as claims.
func WithRoleStore(store guard.RoleStore) Option {
	return func(c *config) { c.roleStore = store }
}

// EmailPassword mounts the self-hosted email/password sign-in provider backed
// by store, alongside Google/Microsoft. The provider reuses the guard issuer,
// so the same JWKS backs all sessions.
func EmailPassword(store guard.CredentialStore) Option {
	return func(c *config) { c.emailPasswordStore = store }
}

// WithGoogleSecret sets the Google client secret, overriding the
// GOOGLE_CLIENT_SECRET environment variable. Omit for a public client
// (PKCE-only exchange).
func WithGoogleSecret(secret string) Option {
	return func(c *config) { c.googleSecret = secret }
}

// WithMicrosoftSecret sets the Microsoft client secret, overriding the
// AZURE_CLIENT_SECRET environment variable. Omit for a public client
// (PKCE-only exchange).
func WithMicrosoftSecret(secret string) Option {
	return func(c *config) { c.microsoftSecret = secret }
}

// WithTenant restricts Microsoft sign-in to a single tenant: the tenant GUID
// or a verified domain. Defaults to "common" (any tenant). When a tenant is
// pinned, guests whose home tenant differs are rejected.
func WithTenant(tenant string) Option {
	return func(c *config) { c.tenant = tenant }
}

// WithSecure marks the session and state cookies Secure. Set in production.
func WithSecure(secure bool) Option {
	return func(c *config) { c.secure = secure }
}

// WithSessionTTL overrides the one-hour default session cookie lifetime and
// the lifetime of guard tokens minted at sign-in.
func WithSessionTTL(ttl time.Duration) Option {
	return func(c *config) { c.sessionTTL = ttl }
}

// WithValidator replaces the automatically constructed boundary validator for
// a provider (name "google" or "microsoft"). Useful for custom validators, e.g.
// national clouds, and avoids the provider discovery network call. It only
// affects the sign-in boundary; it does not add the provider's tokens to
// Auth.Validators.
func WithValidator(name string, v guard.TokenValidator) Option {
	return func(c *config) { c.validators[name] = v }
}

// Setup registers the sign-in page, provider OAuth routes, the guard JWKS
// endpoint, the optional email/password login provider, and logout on mux,
// returning the flow and validators for the auth middlewares. Issuer is
// required.
func Setup(mux *http.ServeMux, opts ...Option) (*Auth, error) {
	cfg := config{
		tenant:     defaultTenant,
		validators: make(map[string]guard.TokenValidator),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.issuerOrigin == "" {
		return nil, fmt.Errorf("auth: Issuer(origin) is required")
	}
	secretsFromEnv(&cfg)

	issuerCfg := guard.IssuerConfig{Issuer: cfg.issuerOrigin, RoleStore: cfg.roleStore}
	if len(cfg.sessionKey) > 0 {
		issuerCfg.PrivateKeyPEM = cfg.sessionKey
	} else {
		slog.Warn("auth: no WithSessionKey configured; an ephemeral signing key will be generated and sessions will reset on restart")
	}
	issuer, err := guard.NewIssuer(issuerCfg)
	if err != nil {
		return nil, err
	}
	result := &Auth{
		Issuer:     issuer,
		Validators: []guard.TokenValidator{issuer},
		JWKSURL:    cfg.issuerOrigin + guard.JWKSPath,
	}

	providers := make([]signin.Provider, 0, 3)

	if cfg.googleClientID != "" {
		google, err := newGoogleValidator(cfg)
		if err != nil {
			return nil, err
		}
		providers = append(providers, signin.Provider{
			Name:         googleProvider,
			Label:        "Google",
			ClientID:     cfg.googleClientID,
			ClientSecret: cfg.googleSecret,
			Endpoint:     googleoauth.Endpoint,
			Validator:    google,
		})
		logSecretless(googleProvider, cfg.googleSecret)
	}

	if cfg.microsoftClientID != "" {
		microsoft, err := newMicrosoftValidator(cfg)
		if err != nil {
			return nil, err
		}
		providers = append(providers, signin.Provider{
			Name:         microsoftProvider,
			Label:        "Microsoft",
			ClientID:     cfg.microsoftClientID,
			ClientSecret: cfg.microsoftSecret,
			Endpoint:     endpoints.AzureAD(cfg.tenant),
			Validator:    microsoft,
		})
		logSecretless(microsoftProvider, cfg.microsoftSecret)
	}

	if cfg.emailPasswordStore != nil {
		baProvider := signin.NewBasicAuthProvider(issuer, cfg.emailPasswordStore)
		if cfg.sessionTTL > 0 {
			baProvider = baProvider.WithTokenTTL(cfg.sessionTTL)
		}
		baProvider.Register(mux)
		providers = append(providers, signin.Provider{
			Name:              basicAuthProvider,
			Label:             basicAuthClientLabel,
			ClientID:          basicAuthClientID,
			Endpoint:          oauth2.Endpoint{AuthURL: baProvider.AuthorizePath(), TokenURL: baProvider.TokenPath()},
			Scopes:            []string{"openid", "email"},
			SignsSessionToken: true,
			Validator:         issuer,
		})
	} else {
		// Issuer-only mode: publish the signing keys so downstream services
		// can validate tokens without a login UI mounted at the origin.
		mux.HandleFunc(guard.JWKSPath, func(w http.ResponseWriter, r *http.Request) {
			keyset, err := issuer.JWKS()
			if err != nil {
				http.Error(w, "No public key available", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			_ = json.NewEncoder(w).Encode(keyset)
		})
	}

	if len(providers) > 0 {
		flow, err := signin.New(signin.Config{
			Providers:  providers,
			Issuer:     issuer,
			SessionTTL: cfg.sessionTTL,
			Secure:     cfg.secure,
		})
		if err != nil {
			return nil, err
		}
		flow.Register(mux)
		result.Flow = flow
	}
	return result, nil
}

func newGoogleValidator(cfg config) (guard.TokenValidator, error) {
	if v, ok := cfg.validators[googleProvider]; ok {
		return v, nil
	}
	v, err := guard.NewGoogleTokenValidator(cfg.googleClientID)
	if err != nil {
		return nil, fmt.Errorf("auth: google: %w", err)
	}
	return v, nil
}

func newMicrosoftValidator(cfg config) (guard.TokenValidator, error) {
	if v, ok := cfg.validators[microsoftProvider]; ok {
		return v, nil
	}
	v, err := guard.NewMicrosoftTokenValidator(cfg.tenant, cfg.microsoftClientID)
	if err != nil {
		return nil, fmt.Errorf("auth: microsoft: %w", err)
	}
	return v, nil
}

// logSecretless notes which providers run as public (PKCE-only) clients, so a
// wrong console registration is visible at startup.
func logSecretless(name, secret string) {
	if secret == "" {
		slog.Info("auth: provider has no client secret; it must be registered as a public client (PKCE)", "provider", name)
	}
}

// secretsFromEnv fills any unset secret from the standard environment
// variables; explicit options always take precedence.
func secretsFromEnv(cfg *config) {
	if cfg.googleSecret == "" {
		cfg.googleSecret = os.Getenv(EnvGoogleSecret)
	}
	if cfg.microsoftSecret == "" {
		cfg.microsoftSecret = os.Getenv(EnvMicrosoftSecret)
	}
}
