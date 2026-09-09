package signin

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hydopt/guard"
	"golang.org/x/oauth2"
)

const (
	defaultSessionTTL = time.Hour
	stateCookieName   = "signin_state"
	stateTTL          = 10 * time.Minute
)

type Config struct {
	Providers []Provider

	// Issuer mints guard session tokens at sign-in. When set, cookies and
	// mode=token responses carry a freshly signed guard token (roles resolved
	// from the issuer's role store) instead of the provider's raw ID token.
	// Leave nil to keep storing provider tokens as before. Providers that sign
	// their own tokens (BasicAuthProvider) always produce guard tokens
	// regardless of this setting.
	Issuer *guard.Issuer

	// SessionTTL is the session cookie Max-Age. Defaults to one hour.
	SessionTTL time.Duration
	// Secure marks session and state cookies Secure. Defaults to false (set to
	// true in production).
	Secure bool
	// HomePath is the fallback redirect target after a successful login.
	// Defaults to "/".
	HomePath string
	// SignInPath is the route that renders the sign-in page. Defaults to "/signin".
	SignInPath string
}

type Flow struct {
	providers  map[string]*Provider
	order      []string
	issuer     *guard.Issuer
	cookieName string
	sessionTTL time.Duration
	secure     bool
	homePath   string
	signInPath string
}

func New(cfg Config) (*Flow, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("signin: at least one provider is required")
	}

	f := &Flow{
		providers:  make(map[string]*Provider, len(cfg.Providers)),
		issuer:     cfg.Issuer,
		cookieName: guard.SessionCookieName,
		sessionTTL: cfg.SessionTTL,
		secure:     cfg.Secure,
		homePath:   cfg.HomePath,
		signInPath: cfg.SignInPath,
	}
	if f.sessionTTL <= 0 {
		f.sessionTTL = defaultSessionTTL
	}
	if f.homePath == "" {
		f.homePath = "/"
	}
	if f.signInPath == "" {
		f.signInPath = "/signin"
	}

	for i := range cfg.Providers {
		p := &cfg.Providers[i]
		if p.Name == "" {
			return nil, fmt.Errorf("signin: provider at index %d has no name", i)
		}
		if _, ok := f.providers[p.Name]; ok {
			return nil, fmt.Errorf("signin: duplicate provider name %q", p.Name)
		}
		if p.ClientID == "" {
			return nil, fmt.Errorf("signin: provider %q has no client ID", p.Name)
		}
		if p.Endpoint.AuthURL == "" || p.Endpoint.TokenURL == "" {
			return nil, fmt.Errorf("signin: provider %q has no endpoint", p.Name)
		}
		if p.Validator == nil {
			return nil, fmt.Errorf("signin: provider %q has no validator", p.Name)
		}
		if len(p.Scopes) == 0 {
			p.Scopes = []string{"openid", "email", "profile"}
		}
		if p.Label == "" {
			p.Label = p.Name
		}
		if p.StartPath == "" {
			p.StartPath = "/auth/" + p.Name
		}
		if p.CallbackPath == "" {
			p.CallbackPath = "/auth/" + p.Name + "/callback"
		}
		f.providers[p.Name] = p
		f.order = append(f.order, p.Name)
	}

	return f, nil
}

func (f *Flow) oauthConfig(p *Provider, r *http.Request) *oauth2.Config {
	redirect := p.RedirectURL
	if redirect == "" {
		redirect = redirectURL(r, p.CallbackPath)
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     absoluteEndpoint(r, p.Endpoint),
		RedirectURL:  redirect,
		Scopes:       p.Scopes,
	}
}

// absoluteEndpoint turns relative AuthURL/TokenURL values into absolute URLs
// based on the incoming request. This lets a provider mount its own local
// endpoints (e.g. the basic-auth login and token routes) without a hardcoded
// origin.
func absoluteEndpoint(r *http.Request, ep oauth2.Endpoint) oauth2.Endpoint {
	origin := requestOrigin(r)
	if ep.AuthURL != "" && !strings.Contains(ep.AuthURL, "://") {
		ep.AuthURL = origin + ep.AuthURL
	}
	if ep.TokenURL != "" && !strings.Contains(ep.TokenURL, "://") {
		ep.TokenURL = origin + ep.TokenURL
	}
	return ep
}

// Provider returns the named provider's configuration.
func (f *Flow) Provider(name string) (Provider, bool) {
	p, ok := f.providers[name]
	if !ok {
		return Provider{}, false
	}
	return *p, true
}

// Providers returns all providers in registration order.
func (f *Flow) Providers() []Provider {
	out := make([]Provider, 0, len(f.order))
	for _, name := range f.order {
		out = append(out, *f.providers[name])
	}
	return out
}

// SessionTTL returns the configured session cookie lifetime.
func (f *Flow) SessionTTL() time.Duration { return f.sessionTTL }

// Secure reports whether cookies are marked Secure.
func (f *Flow) Secure() bool { return f.secure }

// HomePath returns the fallback redirect target after login.
func (f *Flow) HomePath() string { return f.homePath }

// SignInPath returns the sign-in page route.
func (f *Flow) SignInPath() string { return f.signInPath }
