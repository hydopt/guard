package guard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoogleLogin(t *testing.T) {
	var (
		mu        sync.Mutex
		challenge string
	)

	googleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			q := r.URL.Query()
			assert.Equal(t, "desktop-client", q.Get("client_id"))
			assert.Equal(t, "S256", q.Get("code_challenge_method"))
			assert.Contains(t, q.Get("scope"), "openid")
			redirect := q.Get("redirect_uri")
			assert.True(t, strings.HasPrefix(redirect, "http://127.0.0.1:"), redirect)
			mu.Lock()
			challenge = q.Get("code_challenge")
			mu.Unlock()
			http.Redirect(w, r, redirect+"?code=test-code&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
		case "/token":
			assert.NoError(t, r.ParseForm())
			assert.Equal(t, "test-code", r.Form.Get("code"))
			assert.Equal(t, "desktop-client", r.Form.Get("client_id"))
			mu.Lock()
			wantChallenge := challenge
			mu.Unlock()
			assert.Equal(t, wantChallenge, pkceChallenge(r.Form.Get("code_verifier")))
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id_token":"google-id-token"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(googleServer.Close)

	guardServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, TokenExchangePath, r.URL.Path)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "google", r.Form.Get("provider"))
		assert.Equal(t, "google-id-token", r.Form.Get("id_token"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"token":"guard-token","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(guardServer.Close)

	token, err := GoogleLogin(t.Context(), GoogleLoginConfig{
		GuardURL: guardServer.URL,
		ClientID: "desktop-client",
		AuthURL:  googleServer.URL + "/auth",
		TokenURL: googleServer.URL + "/token",
		OpenBrowser: func(authURL string) error {
			resp, err := http.Get(authURL)
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "guard-token", token)
}

func TestGoogleLoginStateMismatch(t *testing.T) {
	googleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect_uri")
		http.Redirect(w, r, redirect+"?code=test-code&state=wrong", http.StatusFound)
	}))
	t.Cleanup(googleServer.Close)

	_, err := GoogleLogin(t.Context(), GoogleLoginConfig{
		GuardURL: "http://127.0.0.1:1",
		ClientID: "desktop-client",
		AuthURL:  googleServer.URL,
		TokenURL: googleServer.URL,
		OpenBrowser: func(authURL string) error {
			resp, err := http.Get(authURL)
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	})
	require.ErrorContains(t, err, "state mismatch")
}

func TestGoogleLoginProviderError(t *testing.T) {
	googleServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect_uri")
		state := url.QueryEscape(r.URL.Query().Get("state"))
		http.Redirect(w, r, redirect+"?error=access_denied&state="+state, http.StatusFound)
	}))
	t.Cleanup(googleServer.Close)

	_, err := GoogleLogin(t.Context(), GoogleLoginConfig{
		GuardURL: "http://127.0.0.1:1",
		ClientID: "desktop-client",
		AuthURL:  googleServer.URL,
		TokenURL: googleServer.URL,
		OpenBrowser: func(authURL string) error {
			resp, err := http.Get(authURL)
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	})
	require.ErrorContains(t, err, "access_denied")
}

func TestGoogleLoginRequiresConfig(t *testing.T) {
	_, err := GoogleLogin(t.Context(), GoogleLoginConfig{ClientID: "client"})
	assert.ErrorContains(t, err, "GuardURL")

	_, err = GoogleLogin(t.Context(), GoogleLoginConfig{GuardURL: "https://auth.example.test"})
	assert.ErrorContains(t, err, "ClientID")

	_, err = GoogleLogin(t.Context(), GoogleLoginConfig{
		GuardURL:   "https://auth.example.test",
		ClientID:   "client",
		ListenAddr: "0.0.0.0:0",
	})
	assert.ErrorContains(t, err, "loopback")
}
