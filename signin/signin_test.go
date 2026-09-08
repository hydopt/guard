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

const validIDToken = "valid-id-token"

type fakeValidator struct {
	wantToken string
}

func (v fakeValidator) ValidateToken(_ context.Context, token string) (*bearer.User, error) {
	if token != v.wantToken {
		return nil, bearer.ErrUnauthorized
	}
	return &bearer.User{
		Id:            "user-1",
		Email:         "someone@example.com",
		VerifiedEmail: true,
		Sub:           "user-1",
	}, nil
}

// newFakeOAuthServer serves /authorize (redirects back with a code) and
// /token (returns an id_token). Parametrized by the issued id_token value.
func newFakeOAuthServer(t *testing.T, idToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		q := redirectURI.Query()
		q.Set("code", "auth-code")
		q.Set("state", r.URL.Query().Get("state"))
		redirectURI.RawQuery = q.Encode()
		http.Redirect(w, r, redirectURI.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "auth-code" {
			http.Error(w, "bad code", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-token",
			"id_token":     idToken,
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

func newServer(t *testing.T, issuedToken string, validator bearer.TokenValidator) (*httptest.Server, *http.Client, *url.URL) {
	t.Helper()
	oauth := newFakeOAuthServer(t, issuedToken)
	if validator == nil {
		validator = fakeValidator{wantToken: issuedToken}
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

// completeLogin performs start -> callback, returning the final redirect target.
func completeLogin(t *testing.T, client *http.Client, server *httptest.Server, next string) string {
	t.Helper()
	resp := get(t, client, server.URL+"/auth/test?next="+url.QueryEscape(next))
	require.Equal(t, http.StatusFound, resp.StatusCode)

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")
	require.NotEmpty(t, state)

	callback := server.URL + "/auth/test/callback?code=auth-code&state=" + url.QueryEscape(state)
	resp = get(t, client, callback)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	return resp.Header.Get("Location")
}

func TestFlow_CompleteLogin(t *testing.T) {
	server, client, serverURL := newServer(t, validIDToken, nil)

	target := completeLogin(t, client, server, "/dashboard")
	assert.Equal(t, "/dashboard", target)
	assert.Equal(t, validIDToken, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))
}

func TestFlow_OpenRedirectBlocked(t *testing.T) {
	for _, evil := range []string{"https://evil.com", "//evil.com"} {
		server, client, _ := newServer(t, validIDToken, nil)
		target := completeLogin(t, client, server, evil)
		assert.Equal(t, "/", target, "next=%q must fall back to home", evil)
	}
}

func TestFlow_DefaultRedirectTarget(t *testing.T) {
	server, client, _ := newServer(t, validIDToken, nil)
	target := completeLogin(t, client, server, "")
	assert.Equal(t, "/", target)
}

func TestFlow_MissingState(t *testing.T) {
	server, client, _ := newServer(t, validIDToken, nil)
	resp := get(t, client, server.URL+"/auth/test/callback?code=auth-code&state=whatever")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_MismatchedState(t *testing.T) {
	server, client, _ := newServer(t, validIDToken, nil)
	// Start a login so a state cookie is present, then present a wrong state.
	resp := get(t, client, server.URL+"/auth/test")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	resp = get(t, client, server.URL+"/auth/test/callback?code=auth-code&state=not-the-state")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_InvalidIDToken(t *testing.T) {
	server, client, _ := newServer(t, "bad-id-token", fakeValidator{wantToken: validIDToken})
	resp := get(t, client, server.URL+"/auth/test")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")

	callback := server.URL + "/auth/test/callback?code=auth-code&state=" + url.QueryEscape(state)
	resp = get(t, client, callback)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_MissingAuthorizationCode(t *testing.T) {
	server, client, _ := newServer(t, validIDToken, nil)
	resp := get(t, client, server.URL+"/auth/test")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")

	callback := server.URL + "/auth/test/callback?state=" + url.QueryEscape(state)
	resp = get(t, client, callback)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestFlow_ProviderError(t *testing.T) {
	server, client, _ := newServer(t, validIDToken, nil)
	resp := get(t, client, server.URL+"/auth/test")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")

	callback := server.URL + "/auth/test/callback?state=" + url.QueryEscape(state) + "&error=access_denied"
	resp = get(t, client, callback)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFlow_ModeToken(t *testing.T) {
	server, client, serverURL := newServer(t, validIDToken, nil)

	resp := get(t, client, server.URL+"/auth/test")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")

	callback := server.URL + "/auth/test/callback?code=auth-code&state=" + url.QueryEscape(state) + "&mode=token"
	resp = get(t, client, callback)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"token":"valid-id-token","token_type":"Bearer","expires_in":3600}`,
		readBody(t, resp))
	assert.Empty(t, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName),
		"mode=token must not set the session cookie")
	stateCookie := findCookie(t, resp, stateCookieName)
	require.NotNil(t, stateCookie, "state cookie must be cleared")
	assert.Equal(t, "", stateCookie.Value)
	assert.LessOrEqual(t, stateCookie.MaxAge, 0)
}

func TestFlow_CookieTtlClampedToTokenExpiry(t *testing.T) {
	exp := time.Now().Add(90 * time.Second)
	idToken := idTokenWithExp(t, exp)
	oauth := newFakeOAuthServer(t, idToken)
	flow, err := New(Config{Providers: []Provider{provider(oauth, fakeValidator{wantToken: idToken})}})
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

	resp := get(t, client, server.URL+"/auth/test?next=%2F")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	state := location.Query().Get("state")
	require.NotEmpty(t, state)

	callback := server.URL + "/auth/test/callback?code=auth-code&state=" + url.QueryEscape(state)
	resp = get(t, client, callback)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Equal(t, "/", resp.Header.Get("Location"))

	cookie := findCookie(t, resp, bearer.SessionCookieName)
	require.NotNil(t, cookie)
	assert.Equal(t, idToken, cookie.Value)
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

func idTokenWithExp(t *testing.T, exp time.Time) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"user-1","exp":%d}`, exp.Unix())))
	return header + "." + payload + ".sig"
}

func TestFlow_Logout(t *testing.T) {
	server, client, serverURL := newServer(t, validIDToken, nil)
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

func TestFlow_Private(t *testing.T) {
	oauth := newFakeOAuthServer(t, validIDToken)
	flow, err := New(Config{Providers: []Provider{provider(oauth, fakeValidator{wantToken: validIDToken})}})
	require.NoError(t, err)

	mux := http.NewServeMux()
	flow.Register(mux)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := bearer.MustGetUserFromCtx(r.Context())
		_, _ = w.Write([]byte(user.Email))
	})
	mux.Handle("/private", bearer.RequireVerifiedEmail(
		[]bearer.TokenValidator{fakeValidator{wantToken: validIDToken}},
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
	assert.Equal(t, validIDToken, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))

	resp := get(t, client, server.URL+"/private")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "someone@example.com", readBody(t, resp))
}

func TestFlow_RequireLogin(t *testing.T) {
	oauth := newFakeOAuthServer(t, validIDToken)
	flow, err := New(Config{Providers: []Provider{provider(oauth, fakeValidator{wantToken: validIDToken})}})
	require.NoError(t, err)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := bearer.MustGetUserFromCtx(r.Context())
		_, _ = w.Write([]byte(user.Email))
	})

	mux := http.NewServeMux()
	flow.Register(mux)
	mux.Handle("/private", flow.RequireLogin(
		[]bearer.TokenValidator{fakeValidator{wantToken: validIDToken}},
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
		req.Header.Set("Authorization", "Bearer "+validIDToken)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "someone@example.com", readBody(t, resp))
	})

	t.Run("passesThroughWithCookie", func(t *testing.T) {
		target := completeLogin(t, client, server, "/private")
		assert.Equal(t, "/private", target)
		assert.Equal(t, validIDToken, sessionCookie(client.Jar, serverURL, bearer.SessionCookieName))

		resp := get(t, client, server.URL+"/private")
		require.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "someone@example.com", readBody(t, resp))
	})
}

func TestFlow_UnknownProvider(t *testing.T) {
	server, client, _ := newServer(t, validIDToken, nil)
	resp := get(t, client, server.URL+"/auth/unknown")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestFlow_RequiresProvider(t *testing.T) {
	_, err := New(Config{})
	assert.Error(t, err)
}

func TestFlow_DefaultPaths(t *testing.T) {
	oauth := newFakeOAuthServer(t, validIDToken)
	flow, err := New(Config{Providers: []Provider{{
		Name:      "demo",
		ClientID:  "client-id",
		Endpoint:  oauth2.Endpoint{AuthURL: oauth.URL + "/authorize", TokenURL: oauth.URL + "/token"},
		Validator: fakeValidator{wantToken: validIDToken},
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
