package signin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hydopt/bearer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// fakeValidator accepts any token (the signature is exercised by the real
// providers). Optionally overrides the resulting user, or rejects with an
// error to simulate a failed validation.
type fakeValidator struct {
	user *bearer.User
	err  error
}

func (v fakeValidator) ValidateToken(_ context.Context, _ string) (*bearer.User, error) {
	if v.err != nil {
		return nil, v.err
	}
	if v.user != nil {
		return v.user, nil
	}
	return &bearer.User{
		Id:            "user-1",
		Email:         "someone@example.com",
		VerifiedEmail: true,
		Sub:           "user-1",
	}, nil
}

// newFakeOAuthServer serves /authorize (redirects back with a code) and
// /token (returns an id_token carrying the nonce from the authorization
// request). The issued token is built by issuedToken, which defaults to a
// valid nonce-bearing JWT.
func newFakeOAuthServer(t *testing.T, issuedToken func(nonce string) string) *httptest.Server {
	t.Helper()
	if issuedToken == nil {
		issuedToken = func(nonce string) string { return signInIDToken(t, nonce) }
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		nonce := r.URL.Query().Get("nonce")
		if nonce == "" {
			http.Error(w, "missing nonce", http.StatusBadRequest)
			return
		}
		q := redirectURI.Query()
		q.Set("code", base64.RawURLEncoding.EncodeToString([]byte(nonce)))
		q.Set("state", r.URL.Query().Get("state"))
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") == "" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		nonce, err := base64.RawURLEncoding.DecodeString(r.Form.Get("code"))
		if err != nil || len(nonce) == 0 {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"id_token":     issuedToken(string(nonce)),
			"token_type":   "Bearer",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func provider(oauth *httptest.Server, validator bearer.TokenValidator) Provider {
	return Provider{
		Name:         "test",
		Label:        "Test",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:  oauth.URL + "/authorize",
			TokenURL: oauth.URL + "/token",
		},
		StartPath:    "/auth/test",
		CallbackPath: "/auth/test/callback",
		Validator:    validator,
	}
}

func newServer(t *testing.T, issuedToken func(nonce string) string, validator bearer.TokenValidator) (*httptest.Server, *http.Client, *url.URL) {
	t.Helper()
	oauth := newFakeOAuthServer(t, issuedToken)
	if validator == nil {
		validator = fakeValidator{}
	}
	flow, err := New(Config{Providers: []Provider{provider(oauth, validator)}})
	require.NoError(t, err)

	mux := http.NewServeMux()
	flow.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return server, client, serverURL
}

func get(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	resp, err := client.Get(rawURL)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

func sessionCookie(jar http.CookieJar, u *url.URL, name string) string {
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// startLogin performs the authorization request and, following the redirect to
// the fake provider, returns the state and code the browser is told to hand
// back to the callback.
func startLogin(t *testing.T, client *http.Client, server *httptest.Server, next string) (state, code string) {
	t.Helper()
	u := server.URL + "/auth/test"
	if next != "" {
		u += "?next=" + url.QueryEscape(next)
	}
	resp := get(t, client, u)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	authorizeURL := resp.Header.Get("Location")
	auth, err := url.Parse(authorizeURL)
	require.NoError(t, err)
	state = auth.Query().Get("state")
	require.NotEmpty(t, state)

	resp = get(t, client, authorizeURL)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code = location.Query().Get("code")
	require.NotEmpty(t, code)
	return state, code
}

func callbackURL(server *httptest.Server, state, code, extra string) string {
	u := server.URL + "/auth/test/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state)
	if extra != "" {
		u += "&" + extra
	}
	return u
}

// completeLogin performs start -> callback, returning the final redirect target.
func completeLogin(t *testing.T, client *http.Client, server *httptest.Server, next string) string {
	t.Helper()
	state, code := startLogin(t, client, server, next)

	resp := get(t, client, callbackURL(server, state, code, ""))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	return resp.Header.Get("Location")
}

func TestFlow_CompleteLogin(t *testing.T) {
	server, client, serverURL := newServer(t, nil, nil)

	target := completeLogin(t, client, server, "/dashboard")
	assert.Equal(t, "/dashboard", target)
	claims := idTokenClaims(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))
	assert.Equal(t, "someone@example.com", claims["email"])
	assert.NotEmpty(t, claims["nonce"], "the token must carry the nonce we sent")
}

func TestFlow_OpenRedirectBlocked(t *testing.T) {
	for _, evil := range []string{"https://evil.com", "//evil.com"} {
		server, client, _ := newServer(t, nil, nil)
		target := completeLogin(t, client, server, evil)
		assert.Equal(t, "/", target, "next=%q must fall back to home", evil)
	}
}

func TestFlow_DefaultRedirectTarget(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)
	target := completeLogin(t, client, server, "")
	assert.Equal(t, "/", target)
}

func TestFlow_MissingState(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)
	resp := get(t, client, server.URL+"/auth/test/callback?code=auth-code&state=whatever")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_MismatchedState(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)
	// Start a login so a state cookie is present, then present a wrong state.
	_, _ = startLogin(t, client, server, "")

	resp := get(t, client, callbackURL(server, "not-the-state", "auth-code", ""))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_InvalidIDToken(t *testing.T) {
	server, client, _ := newServer(t, func(string) string { return "bad-id-token" },
		fakeValidator{err: bearer.ErrUnauthorized})
	state, code := startLogin(t, client, server, "")

	resp := get(t, client, callbackURL(server, state, code, ""))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_MissingAuthorizationCode(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)
	state, _ := startLogin(t, client, server, "")

	resp := get(t, client, server.URL+"/auth/test/callback?state="+url.QueryEscape(state))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestFlow_ProviderError(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)
	state, _ := startLogin(t, client, server, "")

	resp := get(t, client, server.URL+"/auth/test/callback?state="+url.QueryEscape(state)+"&error=access_denied")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_ModeToken(t *testing.T) {
	server, client, serverURL := newServer(t, nil, nil)

	state, code := startLogin(t, client, server, "")
	resp := get(t, client, callbackURL(server, state, code, "mode=token"))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var payload struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type"`
		ExpiresIn int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal([]byte(readBody(t, resp)), &payload))
	assert.Equal(t, "Bearer", payload.TokenType)
	assert.InDelta(t, 3600, payload.ExpiresIn, 30, "expires_in must be the remaining token lifetime")
	claims := idTokenClaims(t, payload.Token)
	assert.Equal(t, "someone@example.com", claims["email"])
	assert.NotEmpty(t, claims["nonce"])
	assert.Empty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName),
		"mode=token must not set the session cookie")
	stateCookie := findCookie(t, resp, stateCookieName)
	require.NotNil(t, stateCookie, "state cookie must be cleared")
	assert.Equal(t, "", stateCookie.Value)
	assert.LessOrEqual(t, stateCookie.MaxAge, 0)
}

func TestFlow_NextWithPipe(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)

	target := completeLogin(t, client, server, "/private?x=a|b")
	assert.Equal(t, "/private?x=a|b", target, "next containing | must survive the state cookie")
}

func TestFlow_Pkce(t *testing.T) {
	server, client, serverURL := newServer(t, nil, nil)

	resp := get(t, client, server.URL+"/auth/test")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	q := location.Query()
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("nonce"))

	var req loginRequest
	raw := sessionCookie(client.Jar, serverURL, stateCookieName)
	require.NotEmpty(t, raw)
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(decoded, &req))
	require.NotEmpty(t, req.Verifier)
	assert.Equal(t, s256Challenge(req.Verifier), q.Get("code_challenge"))
	assert.Equal(t, req.Nonce, q.Get("nonce"), "the authorization request must carry the state cookie's nonce")
}

func TestFlow_NonceMismatch(t *testing.T) {
	// The provider echoes a nonce that differs from the one we sent.
	server, client, _ := newServer(t, func(string) string { return signInIDToken(t, "attacker-controlled-nonce") }, nil)
	state, code := startLogin(t, client, server, "")

	resp := get(t, client, callbackURL(server, state, code, ""))
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_CookieTtlClampedToTokenExpiry(t *testing.T) {
	exp := time.Now().Add(90 * time.Second)
	oauth := newFakeOAuthServer(t, func(nonce string) string { return idTokenWithExp(t, exp, nonce) })
	flow, err := New(Config{Providers: []Provider{provider(oauth, fakeValidator{})}})
	require.NoError(t, err)

	mux := http.NewServeMux()
	flow.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	state, code := startLogin(t, client, server, "/")

	resp := get(t, client, callbackURL(server, state, code, ""))
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "/", resp.Header.Get("Location"))

	cookie := findCookie(t, resp, bearer.SessionCookieName)
	require.NotNil(t, cookie)
	require.NotEmpty(t, cookie.Value)
	assert.GreaterOrEqual(t, cookie.MaxAge, 80)
	assert.LessOrEqual(t, cookie.MaxAge, 90) // clamped to the ~90s token exp
}

func findCookie(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, raw := range resp.Header.Values("Set-Cookie") {
		c, err := http.ParseSetCookie(raw)
		if err == nil && c.Name == name {
			return c
		}
	}
	return nil
}

func idTokenWithExp(t *testing.T, exp time.Time, nonce string) string {
	t.Helper()
	return idTokenWithPayload(t, fmt.Sprintf(`{"sub":"user-1","exp":%d,"nonce":%q}`, exp.Unix(), nonce))
}

// signInIDToken builds the token the fake provider hands back on a successful
// sign-in: a structurally valid JWT carrying the nonce from the authorization
// request (the signature is not verified by the fake validator).
func signInIDToken(t *testing.T, nonce string) string {
	t.Helper()
	return idTokenWithPayload(t, fmt.Sprintf(
		`{"sub":"user-1","email":"someone@example.com","exp":%d,"nonce":%q}`,
		time.Now().Add(time.Hour).Unix(), nonce))
}

func idTokenWithPayload(t *testing.T, payload string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return header + "." + body + ".sig"
}

// idTokenClaims decodes the (unverified) payload of a JWT produced by the
// fake provider.
func idTokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func TestFlow_Logout(t *testing.T) {
	server, client, serverURL := newServer(t, nil, nil)
	completeLogin(t, client, server, "/")

	assert.NotEmpty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))

	req, err := http.NewRequest(http.MethodPost, server.URL+"/auth/logout", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Empty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))
}

func TestFlow_LogoutIgnoresRequestWithoutSessionCookie(t *testing.T) {
	server, client, serverURL := newServer(t, nil, nil)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/auth/logout", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Empty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName),
		"logout without a session cookie (e.g. cross-site CSRF) must not issue anything")
}

func TestFlow_Private(t *testing.T) {
	oauth := newFakeOAuthServer(t, nil)
	flow, err := New(Config{Providers: []Provider{provider(oauth, fakeValidator{})}})
	require.NoError(t, err)

	mux := http.NewServeMux()
	flow.Register(mux)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := bearer.MustGetUserFromCtx(r.Context())
		_, _ = w.Write([]byte(user.Email))
	})
	mux.Handle("/private", bearer.RequireVerifiedEmail(
		[]bearer.TokenValidator{fakeValidator{}},
	)(protected))

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	target := completeLogin(t, client, server, "/private")
	assert.Equal(t, "/private", target)
	assert.NotEmpty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))

	resp := get(t, client, server.URL+"/private")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "someone@example.com", readBody(t, resp))
}

func TestFlow_RequireLogin(t *testing.T) {
	oauth := newFakeOAuthServer(t, nil)
	flow, err := New(Config{Providers: []Provider{provider(oauth, fakeValidator{})}})
	require.NoError(t, err)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := bearer.MustGetUserFromCtx(r.Context())
		_, _ = w.Write([]byte(user.Email))
	})

	mux := http.NewServeMux()
	flow.Register(mux)
	mux.Handle("/private", flow.RequireLogin(
		[]bearer.TokenValidator{fakeValidator{}},
	)(protected))

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	t.Run("redirectsUnauthenticatedGet", func(t *testing.T) {
		resp := get(t, client, server.URL+"/private")
		require.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, "/signin?next=%2Fprivate", resp.Header.Get("Location"))
	})

	t.Run("signInPageForwardsNext", func(t *testing.T) {
		resp := get(t, client, server.URL+"/signin?next=%2Fprivate")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Contains(t, readBody(t, resp), `href="/auth/test?next=%2Fprivate"`)
	})

	t.Run("preservesQueryString", func(t *testing.T) {
		resp := get(t, client, server.URL+"/private?tab=2")
		require.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, "/signin?next=%2Fprivate%3Ftab%3D2", resp.Header.Get("Location"))
	})

	t.Run("rejectsUnauthenticatedPost", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/private", strings.NewReader("x"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("passesThroughWithBearer", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/private", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer anything-works-with-the-fake-validator")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "someone@example.com", readBody(t, resp))
	})

	t.Run("passesThroughWithCookie", func(t *testing.T) {
		target := completeLogin(t, client, server, "/private")
		assert.Equal(t, "/private", target)
		assert.NotEmpty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))

		resp := get(t, client, server.URL+"/private")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "someone@example.com", readBody(t, resp))
	})
}

func TestFlow_UnknownProvider(t *testing.T) {
	server, client, _ := newServer(t, nil, nil)
	resp := get(t, client, server.URL+"/auth/unknown")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestFlow_RequiresProvider(t *testing.T) {
	_, err := New(Config{})
	assert.Error(t, err)
}

func TestFlow_DefaultPaths(t *testing.T) {
	oauth := newFakeOAuthServer(t, nil)
	flow, err := New(Config{Providers: []Provider{{
		Name:      "demo",
		ClientID:  "client-id",
		Endpoint:  oauth2.Endpoint{AuthURL: oauth.URL + "/authorize", TokenURL: oauth.URL + "/token"},
		Validator: fakeValidator{},
	}}})
	require.NoError(t, err)
	assert.Equal(t, "/auth/demo", flow.providers["demo"].StartPath)
	assert.Equal(t, "/auth/demo/callback", flow.providers["demo"].CallbackPath)
	assert.Equal(t, "demo", flow.providers["demo"].Label)
	assert.Equal(t, []string{"openid", "email", "profile"}, flow.providers["demo"].Scopes)
	assert.Equal(t, bearer.SessionCookieName, flow.cookieName)
	assert.Equal(t, time.Hour, flow.sessionTTL)
	assert.Equal(t, "/", flow.homePath)
	assert.Equal(t, "/signin", flow.signInPath)
}
