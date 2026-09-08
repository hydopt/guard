package signin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hydopt/bearer"
	"github.com/hydopt/bearer/components"
	"golang.org/x/oauth2"
)

// RequireLogin redirects requests without any credentials to the sign-in page
// (with the original path as ?next=), so the browser can log in and be sent
// back. Requests that carry credentials but fail validation still get a 401,
// as do non-GET requests without credentials (a redirect would silently turn a
// POST into a GET and lose the body).
func (f *Flow) RequireLogin(validators []bearer.TokenValidator) bearer.Middleware {
	auth := bearer.RequireVerifiedEmail(validators)
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
		next := safeRedirect(r.URL.Query().Get("next"), f.homePath)
		f.writeStateCookie(w, state+"|"+next)
		http.Redirect(w, r, f.oauthConfig(p, r).AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusFound)
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
		state, next, found := strings.Cut(stateCookie.Value, "|")
		if !found || state == "" || state != r.URL.Query().Get("state") {
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}
		f.clearStateCookie(w)

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		token, err := f.oauthConfig(p, r).Exchange(r.Context(), code)
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
		if _, err := p.Validator.ValidateToken(r.Context(), idToken); err != nil {
			slog.Info("token validation failed", "provider", p.Name, "error", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		f.writeSessionCookie(w, idToken)

		if r.URL.Query().Get("mode") == "token" {
			writeTokenResponse(w, idToken, f.sessionTTL)
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
	}
}

func (f *Flow) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f.clearSessionCookie(w)
	http.Redirect(w, r, f.homePath, http.StatusFound)
}

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

func redirectURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: r.Host, Path: path}
	return u.String()
}
