package signin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hydopt/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// newBasicAuthServer wires a basic-auth provider (issuer + credential store)
// plus the sign-in flow, returning the server, a cookie jar, and a parser.
func newBasicAuthServer(t *testing.T) (*httptest.Server, *http.Client, *url.URL, *guard.Issuer) {
	t.Helper()
	issuer, err := guard.NewIssuer(guard.IssuerConfig{
		Issuer: "https://auth.example.test",
	})
	require.NoError(t, err)
	store := guard.NewInMemoryCredentialStore(map[string]string{
		"alice@example.com": "s3cret",
	})

	baProvider := NewBasicAuthProvider(issuer, store)

	flow, err := New(Config{Providers: []Provider{{
		Name:              "basic-auth",
		Label:             "Basic Auth",
		ClientID:          "basic-auth",
		Endpoint:          oauth2.Endpoint{AuthURL: baProvider.AuthorizePath(), TokenURL: baProvider.TokenPath()},
		Scopes:            []string{"openid", "email"},
		SignsSessionToken: true,
		Validator:         issuer,
	}}})
	require.NoError(t, err)

	mux := http.NewServeMux()
	baProvider.Register(mux)
	flow.Register(mux)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := guard.MustGetUserFromCtx(r.Context())
		_, _ = w.Write([]byte(user.Email))
	})
	mux.Handle("/private", guard.RequireVerifiedEmail([]guard.TokenValidator{issuer})(protected))

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
	return server, client, serverURL, issuer
}

// startBasicAuthLogin hits /auth/basic-auth, follows the redirect, and returns
// the authorize URL plus the login form fields it embeds.
func startBasicAuthLogin(t *testing.T, client *http.Client, server *httptest.Server) (authorizeURL *url.URL, form *url.Values) {
	t.Helper()
	resp := get(t, client, server.URL+"/auth/basic-auth")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	authorizeURL, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)

	resp = get(t, client, authorizeURL.String())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := readBody(t, resp)
	require.Contains(t, body, `name="email"`)
	require.Contains(t, body, `name="password"`)

	form = &url.Values{}
	hidden := []string{"client_id", "response_type", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method", "nonce"}
	for _, h := range hidden {
		if val := authorizeURL.Query().Get(h); val != "" {
			form.Set(h, val)
		}
	}
	return authorizeURL, form
}

// submitLogin POSTs the login form with the given credentials and returns the
// response.
func submitLogin(t *testing.T, client *http.Client, authorizeURL *url.URL, form *url.Values, email, password string) *http.Response {
	t.Helper()
	form = cloneValuesPtr(form)
	form.Set("email", email)
	form.Set("password", password)
	req, err := http.NewRequest(http.MethodPost, authorizeURL.String(), strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func cloneValuesPtr(v *url.Values) *url.Values {
	out := &url.Values{}
	for k, vs := range *v {
		for _, val := range vs {
			out.Add(k, val)
		}
	}
	return out
}

func TestBasicAuth_CompleteLogin(t *testing.T) {
	server, client, serverURL, _ := newBasicAuthServer(t)

	authorizeURL, form := startBasicAuthLogin(t, client, server)
	resp := submitLogin(t, client, authorizeURL, form, "alice@example.com", "s3cret")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/auth/basic-auth/callback", callback.Path)
	require.NotEmpty(t, callback.Query().Get("code"))
	require.Equal(t, form.Get("state"), callback.Query().Get("state"))

	// Complete the OAuth2 dance: hit the callback, which exchanges the code.
	resp = get(t, client, callback.String())
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "/", resp.Header.Get("Location"))

	// The session cookie is now a valid basic-auth token for alice.
	session := sessionCookie(client.Jar, serverURL, guard.SessionCookieName)
	require.NotEmpty(t, session)
	claims := idTokenClaims(t, session)
	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Equal(t, "https://auth.example.test", claims["iss"])
	assert.Equal(t, form.Get("nonce"), claims["nonce"])

	// The protected endpoint accepts the cookie.
	resp = get(t, client, server.URL+"/private")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "alice@example.com", readBody(t, resp))
}

func TestBasicAuth_WrongPassword(t *testing.T) {
	server, client, _, _ := newBasicAuthServer(t)

	authorizeURL, form := startBasicAuthLogin(t, client, server)
	resp := submitLogin(t, client, authorizeURL, form, "alice@example.com", "wrong")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "Invalid email or password")
}

func TestBasicAuth_UnknownEmail(t *testing.T) {
	server, client, _, _ := newBasicAuthServer(t)

	authorizeURL, form := startBasicAuthLogin(t, client, server)
	resp := submitLogin(t, client, authorizeURL, form, "mallory@example.com", "s3cret")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "Invalid email or password")
}

func TestBasicAuth_MissingFields(t *testing.T) {
	server, client, _, _ := newBasicAuthServer(t)

	authorizeURL, form := startBasicAuthLogin(t, client, server)
	resp := submitLogin(t, client, authorizeURL, form, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, readBody(t, resp), "Email and password are required")
}

func TestBasicAuth_OpenRedirectBlocked(t *testing.T) {
	server, client, _, _ := newBasicAuthServer(t)

	// Tamper with the redirect_uri to an external origin.
	authorizeURL, form := startBasicAuthLogin(t, client, server)
	form.Set("redirect_uri", "https://evil.example/callback")
	resp := submitLogin(t, client, authorizeURL, form, "alice@example.com", "s3cret")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBasicAuth_CodeSingleUse(t *testing.T) {
	server, client, _, _ := newBasicAuthServer(t)

	authorizeURL, form := startBasicAuthLogin(t, client, server)
	resp := submitLogin(t, client, authorizeURL, form, "alice@example.com", "s3cret")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := callback.Query().Get("code")
	require.NotEmpty(t, code)

	// First exchange succeeds and sets the session.
	resp = get(t, client, callback.String())
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Reusing the code must fail.
	resp = get(t, client, callback.String())
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBasicAuth_BearerTokenValidation(t *testing.T) {
	server, _, _, issuer := newBasicAuthServer(t)

	// A token issued programmatically for any subject works through the
	// middleware, since the validator only checks the signature/issuer.
	token, err := issuer.SignToken("alice@example.com", time.Hour)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/private", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", string(b))
}

func TestBasicAuth_ModeToken(t *testing.T) {
	server, client, serverURL, _ := newBasicAuthServer(t)

	authorizeURL, form := startBasicAuthLogin(t, client, server)
	resp := submitLogin(t, client, authorizeURL, form, "alice@example.com", "s3cret")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	q := callback.Query()
	q.Set("mode", "token")
	callback.RawQuery = q.Encode()

	resp = get(t, client, callback.String())
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var payload struct {
		Token     string `json:"token"`
		TokenType string `json:"token_type"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	assert.Equal(t, "Bearer", payload.TokenType)

	claims := idTokenClaims(t, payload.Token)
	assert.Equal(t, "alice@example.com", claims["email"])
	assert.Empty(t, sessionCookie(client.Jar, serverURL, guard.SessionCookieName),
		"mode=token must not set the session cookie")
}
