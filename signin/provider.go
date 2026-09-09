package signin

import (
	"golang.org/x/oauth2"

	"github.com/hydopt/guard"
)

type Provider struct {
	Name         string
	Label        string
	ClientID     string
	ClientSecret string
	// RedirectURL is the absolute callback URL registered with the provider.
	// Leave empty to derive it from the incoming request (scheme + Host +
	// CallbackPath), which is convenient in development.
	RedirectURL string
	Endpoint    oauth2.Endpoint
	// Scopes defaults to ["openid", "email", "profile"] when empty.
	Scopes []string

	StartPath    string
	CallbackPath string

	// SignsSessionToken marks a provider whose sign-in flow already produces a
	// guard session token (e.g. BasicAuthProvider, which mints one in its local
	// token endpoint). The callback then stores that token as-is instead of
	// minting a second one when Config.Issuer is set.
	SignsSessionToken bool

	Validator guard.TokenValidator
}
