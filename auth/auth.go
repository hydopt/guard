// Package auth wires the sign-in flow and Google/Microsoft token validators
// into a http.ServeMux with sensible defaults, so a typical app needs one
// call instead of assembling providers and endpoints by hand.
package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hydopt/bearer"
	"github.com/hydopt/bearer/signin"
	"golang.org/x/oauth2/endpoints"
	googleoauth "golang.org/x/oauth2/google"
)

const (
	googleProvider    = "google"
	microsoftProvider = "microsoft"
	defaultTenant     = "common"
)

// Env vars consulted for the confidential-client secrets when no explicit
// option is given. Leave unset for public clients, where PKCE alone protects
// the code exchange.
const (
	EnvGoogleSecret    = "GOOGLE_CLIENT_SECRET"
	EnvMicrosoftSecret = "AZURE_CLIENT_SECRET"
)

// Auth is what Setup returns: the registered sign-in flow plus the validators
// it constructed, ready to feed the bearer middlewares.
type Auth struct {
	Flow       *signin.Flow
	Validators []bearer.TokenValidator
}

// Option configures Setup.
type Option func(*config)

type config struct {
	googleClientID    string
	microsoftClientID string
	googleSecret      string
	microsoftSecret   string
	tenant            string
	secure            bool
	sessionTTL        time.Duration
	validators        map[string]bearer.TokenValidator
}

// Google enables the Google sign-in provider for the given OAuth client ID.
func Google(clientID string) Option {
	return func(c *config) { c.googleClientID = clientID }
}

// Microsoft enables the Microsoft Entra ID sign-in provider for the given
// OAuth client ID. Uses the multi-tenant "common" audience unless overridden
// with WithTenant.
func Microsoft(clientID string) Option {
	return func(c *config) { c.microsoftClientID = clientID }
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

// WithSessionTTL overrides the one-hour default session cookie lifetime. The
// cookie never outlives the ID token it stores.
func WithSessionTTL(ttl time.Duration) Option {
	return func(c *config) { c.sessionTTL = ttl }
}

// WithValidator replaces the automatically constructed validator for a
// provider (name "google" or "microsoft"). Useful for custom validators, e.g.
// national clouds, and avoids the provider discovery network call.
func WithValidator(name string, v bearer.TokenValidator) Option {
	return func(c *config) { c.validators[name] = v }
}

// Setup registers the sign-in page, the Google/Microsoft OAuth routes, and
// logout on mux, and returns the flow and validators for the bearer
// middlewares. At least one of Google or Microsoft must be configured.
func Setup(mux *http.ServeMux, opts ...Option) (*Auth, error) {
	cfg := config{tenant: defaultTenant}
	cfg.validators = make(map[string]bearer.TokenValidator)
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.googleClientID == "" && cfg.microsoftClientID == "" {
		return nil, fmt.Errorf("auth: at least one of Google or Microsoft must be configured")
	}
	secretsFromEnv(&cfg)

	providers := make([]signin.Provider, 0, 2)
	validators := make([]bearer.TokenValidator, 0, 2)

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
		validators = append(validators, google)
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
		validators = append(validators, microsoft)
		logSecretless(microsoftProvider, cfg.microsoftSecret)
	}

	flow, err := signin.New(signin.Config{
		Providers:  providers,
		SessionTTL: cfg.sessionTTL,
		Secure:     cfg.secure,
	})
	if err != nil {
		return nil, err
	}
	flow.Register(mux)
	return &Auth{Flow: flow, Validators: validators}, nil
}

func newGoogleValidator(cfg config) (bearer.TokenValidator, error) {
	if v, ok := cfg.validators[googleProvider]; ok {
		return v, nil
	}
	v, err := bearer.NewGoogleTokenValidator(cfg.googleClientID)
	if err != nil {
		return nil, fmt.Errorf("auth: google: %w", err)
	}
	return v, nil
}

func newMicrosoftValidator(cfg config) (bearer.TokenValidator, error) {
	if v, ok := cfg.validators[microsoftProvider]; ok {
		return v, nil
	}
	v, err := bearer.NewMicrosoftTokenValidator(cfg.tenant, cfg.microsoftClientID)
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
