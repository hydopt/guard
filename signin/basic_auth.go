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
	"sync"
	"time"

	"github.com/hydopt/guard"
	"github.com/hydopt/guard/components"
)

const (
	defaultAuthorizePath = "/auth/basic-auth/authorize"
	defaultTokenPath     = "/auth/basic-auth/token"
	defaultTokenTTL      = time.Hour
	codeTTL              = 60 * time.Second
)

// BasicAuthProvider serves the local OAuth2 authorization-code endpoints that
// back the basic-auth sign-in option: a login form, a token endpoint, and a
// JWKS endpoint. It is paired with a *guard.Issuer that mints the guard session
// tokens handed out at its token endpoint.
type BasicAuthProvider struct {
	Issuer *guard.Issuer
	Store  guard.CredentialStore
	// TokenTTL is how long issued tokens live. Defaults to one hour.
	TokenTTL time.Duration

	authorizePath string
	tokenPath     string

	mu    sync.Mutex
	codes map[string]*pendingAuth
}

// pendingAuth tracks one authorization code until it is exchanged.
type pendingAuth struct {
	email         string
	codeChallenge string
	nonce         string
	redirectURI   string
	expiresAt     time.Time
}

// NewBasicAuthProvider builds a provider that mints guard tokens with issuer
// and authenticates against store. The issuer and the credential store must not
// be nil.
func NewBasicAuthProvider(issuer *guard.Issuer, store guard.CredentialStore) *BasicAuthProvider {
	return &BasicAuthProvider{
		Issuer:        issuer,
		Store:         store,
		TokenTTL:      defaultTokenTTL,
		authorizePath: defaultAuthorizePath,
		tokenPath:     defaultTokenPath,
		codes:         make(map[string]*pendingAuth),
	}
}

// WithTokenTTL overrides the default one-hour token lifetime.
func (p *BasicAuthProvider) WithTokenTTL(ttl time.Duration) *BasicAuthProvider {
	if ttl > 0 {
		p.TokenTTL = ttl
	}
	return p
}

// Register adds the authorize, token, and JWKS routes to mux.
func (p *BasicAuthProvider) Register(mux *http.ServeMux) {
	mux.HandleFunc(p.authorizePath, p.handleAuthorize)
	mux.HandleFunc(p.tokenPath, p.handleToken)
	mux.HandleFunc(guard.JWKSPath, p.handleJWKS)
}

// AuthorizePath returns the mounted login/authorize route.
func (p *BasicAuthProvider) AuthorizePath() string { return p.authorizePath }

// TokenPath returns the mounted token route.
func (p *BasicAuthProvider) TokenPath() string { return p.tokenPath }

func (p *BasicAuthProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.renderLogin(w, r)
	case http.MethodPost:
		p.processLogin(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *BasicAuthProvider) renderLogin(w http.ResponseWriter, r *http.Request) {
	hidden := oauthParams(r.URL.Query())
	if len(hidden) == 0 {
		http.Error(w, "Missing authorization parameters", http.StatusBadRequest)
		return
	}
	components.BasicAuthLoginHandler(components.BasicAuthLoginData{Hidden: hidden}).ServeHTTP(w, r)
}

func (p *BasicAuthProvider) processLogin(w http.ResponseWriter, r *http.Request) {
	// Every OAuth2 param is replayed as a hidden form field, so the POST body
	// carries both them and the credentials.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	hidden := oauthParams(mergedParams(r))
	if len(hidden) == 0 {
		http.Error(w, "Missing authorization parameters", http.StatusBadRequest)
		return
	}
	responseType := r.Form.Get("response_type")
	if responseType != "" && responseType != "code" {
		http.Error(w, "Unsupported response_type", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.Form.Get("email"))
	password := r.Form.Get("password")
	if email == "" || password == "" {
		p.renderLoginError(w, r, hidden, "Email and password are required.", email)
		return
	}

	if err := p.Store.Authenticate(r.Context(), email, password); err != nil {
		slog.Info("basic-auth: login failed", "error", err)
		p.renderLoginError(w, r, hidden, "Invalid email or password.", email)
		return
	}

	redirectURI := r.Form.Get("redirect_uri")
	if !sameOriginAs(r, redirectURI) {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	code, err := newAuthCode()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	p.mu.Lock()
	p.codes[code] = &pendingAuth{
		email:         email,
		codeChallenge: r.Form.Get("code_challenge"),
		nonce:         r.Form.Get("nonce"),
		redirectURI:   redirectURI,
		expiresAt:     time.Now().Add(codeTTL),
	}
	p.mu.Unlock()

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", r.Form.Get("state"))
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (p *BasicAuthProvider) renderLoginError(w http.ResponseWriter, r *http.Request, hidden []components.HiddenField, msg, email string) {
	data := components.BasicAuthLoginData{
		Error:  msg,
		Email:  email,
		Hidden: hidden,
	}
	components.BasicAuthLoginHandler(data).ServeHTTP(w, r)
}

func (p *BasicAuthProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "malformed form body")
		return
	}
	if r.Form.Get("grant_type") != "authorization_code" {
		writeTokenError(w, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	code := r.Form.Get("code")
	if code == "" {
		writeTokenError(w, "invalid_request", "missing code")
		return
	}

	p.mu.Lock()
	pend, ok := p.codes[code]
	if ok {
		delete(p.codes, code) // single use
	}
	p.mu.Unlock()
	if !ok || time.Now().After(pend.expiresAt) {
		writeTokenError(w, "invalid_grant", "code not found or expired")
		return
	}

	if !validPKCE(pend.codeChallenge, r.Form.Get("code_verifier")) {
		writeTokenError(w, "invalid_grant", "PKCE verification failed")
		return
	}

	idToken, err := p.Issuer.SignToken(pend.email, p.TokenTTL, guard.WithNonce(pend.nonce))
	if err != nil {
		slog.Error("basic-auth: token signing failed", "error", err)
		writeTokenError(w, "server_error", "token signing failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": idToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   int(p.TokenTTL.Seconds()),
	})
}

// handleJWKS publishes the issuer's public key in JWK Set form.
func (p *BasicAuthProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	keyset, err := p.Issuer.JWKS()
	if err != nil {
		http.Error(w, "No public key available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(keyset)
}

func writeTokenError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// oauthParams extracts the OAuth2 authorization request parameters that must
// be carried through the login form as hidden fields.
func oauthParams(v url.Values) []components.HiddenField {
	keys := []string{"client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "nonce", "access_type"}
	out := make([]components.HiddenField, 0, len(keys))
	for _, k := range keys {
		if val := v.Get(k); val != "" {
			out = append(out, components.HiddenField{Name: k, Value: val})
		}
	}
	return out
}

// mergedParams combines the query string and the POSTed form, letting the
// hidden fields drive the flow. Credentials are excluded.
func mergedParams(r *http.Request) url.Values {
	merged := url.Values{}
	for k, vs := range r.URL.Query() {
		for _, v := range vs {
			merged.Add(k, v)
		}
	}
	for k, vs := range r.Form {
		for _, v := range vs {
			if k != "email" && k != "password" {
				merged.Set(k, v)
			}
		}
	}
	return merged
}

// validPKCE recomputes the S256 challenge from the verifier and compares it
// to the challenge stored with the code.
func validPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return challenge == base64.RawURLEncoding.EncodeToString(sum[:])
}

// sameOriginAs reports whether raw is an absolute URL for the current host,
// guarding the login form against open-redirect abuse of redirect_uri.
func sameOriginAs(r *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); fwd != "" {
		scheme = fwd
	}
	if !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	host := r.Host
	if fwd := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		host = fwd
	}
	return strings.EqualFold(u.Host, host)
}

func newAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
