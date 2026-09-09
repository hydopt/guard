package signin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hydopt/guard"
	"github.com/hydopt/guard/components"
	"golang.org/x/oauth2"
)

// RequireLogin redirects requests without any credentials to the sign-in page
// (with the original path as ?next=), so the browser can log in and be sent
// back. Requests that carry credentials but fail validation still get a 401,
// as do non-GET requests without credentials (a redirect would silently turn a
// POST into a GET and lose the body).
func (f *Flow) RequireLogin(validators []guard.TokenValidator) guard.Middleware {
	auth := guard.RequireVerifiedEmail(validators)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if f.hasCredentials(r) {
				auth(next).ServeHTTP(w, r)
				return
			}
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				nextURL := f.signInPath + "?next=" + url.QueryEscape(r.URL.RequestURI())
				http.Redirect(w, r, nextURL, http.StatusFound)
				return
			}
			http.Error(w, "Not authorized", http.StatusUnauthorized)
		})
	}
}

func (f *Flow) hasCredentials(r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return true
	}
	_, err := r.Cookie(f.cookieName)
	return err == nil
}

// Register adds the sign-in page, the per-provider OAuth start and callback
// routes, and the logout route to mux.
func (f *Flow) Register(mux *http.ServeMux) {
	mux.HandleFunc(f.signInPath, f.handleSignIn)
	for _, name := range f.order {
		p := f.providers[name]
		mux.HandleFunc(p.StartPath, f.handleStart(p))
		mux.HandleFunc(p.CallbackPath, f.handleCallback(p))
	}
	mux.HandleFunc("/auth/logout", f.handleLogout)
}

func (f *Flow) handleSignIn(w http.ResponseWriter, r *http.Request) {
	providers := make([]components.Provider, 0, len(f.order))
	for _, name := range f.order {
		p := f.providers[name]
		providers = append(providers, components.Provider{
			Name:      p.Name,
			Label:     p.Label,
			StartPath: p.StartPath,
		})
	}
	components.SignInHandler(providers).ServeHTTP(w, r)
}

func (f *Flow) handleStart(p *Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := newState()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		verifier, err := newState()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		nonce, err := newState()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		next := safeRedirect(r.URL.Query().Get("next"), f.homePath)
		f.writeStateCookie(w, loginRequest{State: state, Next: next, Verifier: verifier, Nonce: nonce})
		http.Redirect(w, r, f.oauthConfig(p, r).AuthCodeURL(
			state,
			oauth2.AccessTypeOnline,
			oauth2.SetAuthURLParam("nonce", nonce),
			oauth2.SetAuthURLParam("code_challenge", s256Challenge(verifier)),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		), http.StatusFound)
	}
}

func (f *Flow) handleCallback(p *Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			slog.Info("provider returned an error", "error", errParam)
			http.Error(w, "Authorization failed", http.StatusUnauthorized)
			return
		}

		stateCookie, err := r.Cookie(stateCookieName)
		if err != nil {
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(stateCookie.Value)
		if err != nil {
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}
		var req loginRequest
		if err := json.Unmarshal(decoded, &req); err != nil || req.State == "" || req.State != r.URL.Query().Get("state") {
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}
		f.clearStateCookie(w)

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		token, err := f.oauthConfig(p, r).Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", req.Verifier))
		if err != nil {
			slog.Info("token exchange failed", "provider", p.Name, "error", err)
			http.Error(w, "Token exchange failed", http.StatusUnauthorized)
			return
		}
		idToken, ok := token.Extra("id_token").(string)
		if !ok || idToken == "" {
			slog.Info("token response missing id_token", "provider", p.Name)
			http.Error(w, "Token response missing id_token", http.StatusUnauthorized)
			return
		}
		user, err := p.Validator.ValidateToken(r.Context(), idToken)
		if err != nil {
			slog.Info("token validation failed", "provider", p.Name, "error", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Bind the ID token to this request: the token must echo the nonce we
		// sent with the authorization request. Prevented token substitution and
		// replay across separate sign-ins.
		if nonce, ok := idTokenNonce(idToken); !ok || nonce != req.Nonce {
			slog.Info("token nonce mismatch", "provider", p.Name)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		sessionToken, ttl, err := f.sessionToken(p, user, idToken)
		if err != nil {
			slog.Error("session token minting failed", "provider", p.Name, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if r.URL.Query().Get("mode") == "token" {
			writeTokenResponse(w, sessionToken, ttl)
			return
		}

		f.writeSessionCookie(w, sessionToken, ttl)
		http.Redirect(w, r, req.Next, http.StatusFound)
	}
}

// sessionToken decides what goes into the session cookie (and mode=token
// responses). Providers that already signed a guard token (SignsSessionToken)
// store it as-is. Otherwise, when Config.Issuer is set, a guard token is minted
// for the validated user (roles resolved from the role store). Without an
// issuer, the provider's raw ID token is stored (legacy behavior) and the
// cookie lifetime is clamped so it never outlives the token.
func (f *Flow) sessionToken(p *Provider, user *guard.User, idToken string) (token string, ttl time.Duration, err error) {
	if p.SignsSessionToken {
		return idToken, sessionCookieTTL(f.sessionTTL, idToken), nil
	}
	if f.issuer != nil {
		opts := []guard.TokenOption{guard.WithProvider(p.Name)}
		if len(user.Roles) > 0 {
			opts = append(opts, guard.WithRoles(user.Roles))
		}
		minted, err := f.issuer.SignToken(user.Email, f.sessionTTL, opts...)
		if err != nil {
			return "", 0, err
		}
		return minted, f.sessionTTL, nil
	}
	return idToken, sessionCookieTTL(f.sessionTTL, idToken), nil
}

// loginRequest is what the state cookie holds across the OAuth round trip:
// the CSRF state, the safe same-origin return target, the PKCE code verifier,
// and the nonce that binds the returned ID token to this request. JSON keeps
// any character safe in the cookie value.
type loginRequest struct {
	State    string `json:"state"`
	Next     string `json:"next,omitempty"`
	Verifier string `json:"verifier,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// handleLogout only honours the logout if the request carries the session
// cookie. A cross-site form POST cannot send the SameSite=Lax session cookie,
// so this both ignores meaningless logouts for signed-out visitors and makes
// logout CSRF ineffective.
func (f *Flow) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, err := r.Cookie(f.cookieName); err != nil {
		http.Redirect(w, r, f.homePath, http.StatusFound)
		return
	}
	f.clearSessionCookie(w)
	http.Redirect(w, r, f.homePath, http.StatusFound)
}

// writeTokenResponse reports the token together with its remaining lifetime.
func writeTokenResponse(w http.ResponseWriter, token string, ttl time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": int(ttl.Seconds()),
	})
}

func newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// safeRedirect only allows same-origin targets (paths starting with a single
// "/") and falls back otherwise, preventing open redirects.
func safeRedirect(target, fallback string) string {
	target = strings.TrimSpace(target)
	if target == "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return fallback
	}
	return target
}

// redirectURL builds the absolute callback URL. Scheme and host come from the
// request, honoring the forwarded headers set by TLS-terminating proxies. The
// forwarded values only shape the redirect_uri sent to the authorization
// server, which validates it against the registered callback, so a spoofed
// header cannot be abused.
func redirectURL(r *http.Request, path string) string {
	return requestOrigin(r) + path
}

// requestOrigin is the scheme://host prefix for the current request, honoring
// the X-Forwarded-* headers set by TLS-terminating proxies.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); fwd != "" {
		scheme = fwd
	}

	host := r.Host
	if fwd := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		host = fwd
	}

	return scheme + "://" + host
}

func firstHeaderValue(v string) string {
	if v == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(v, ",")[0])
}
