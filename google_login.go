package guard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	// TokenExchangePath is where a local program trades a provider ID token for
	// a guard session token.
	TokenExchangePath = "/auth/token"

	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"

	defaultLoginTimeout = 5 * time.Minute
)

// GoogleLoginConfig configures GoogleLogin.
type GoogleLoginConfig struct {
	// GuardURL is the guard origin, e.g. https://auth.example.com. The token
	// exchange endpoint is GuardURL + TokenExchangePath.
	GuardURL string
	// ClientID is a Google OAuth "Desktop app" client ID. Create one in the
	// Google Cloud console; the loopback flow needs no redirect URI
	// registration.
	ClientID string
	// ClientSecret is optional: desktop clients are public clients. Supply the
	// desktop client's secret if your Google project requires it for the token
	// exchange.
	ClientSecret string
	// Scopes defaults to ["openid", "email", "profile"].
	Scopes []string
	// OpenBrowser opens sign-in in the system browser. When nil, the OS opener
	// is used and the URL is printed if that fails.
	OpenBrowser func(authURL string) error
	// HTTPClient is used for Google and guard requests. Defaults to a client
	// with a 30 second timeout.
	HTTPClient *http.Client
	// ListenAddr is where the loopback callback server binds. Defaults to
	// 127.0.0.1:0 (a random port).
	ListenAddr string
	// AuthURL and TokenURL override the Google endpoints. Intended for tests.
	AuthURL  string
	TokenURL string
	// Timeout bounds the whole login when ctx has no deadline. Defaults to five
	// minutes.
	Timeout time.Duration
}

// GoogleLogin signs in locally through Google's desktop OAuth flow and returns
// a guard Bearer token for the guard service at GuardURL:
//
//	token, err := guard.GoogleLogin(ctx, guard.GoogleLoginConfig{
//		GuardURL: "https://auth.example.com",
//		ClientID: "123-abc.apps.googleusercontent.com",
//	})
//	req.Header.Set("Authorization", "Bearer "+token)
//
// It binds a loopback listener, opens the system browser, waits for Google's
// redirect, exchanges the authorization code with PKCE, and then trades the
// resulting Google ID token for a guard token at GuardURL's
// TokenExchangePath. Nothing is stored on disk.
func GoogleLogin(ctx context.Context, cfg GoogleLoginConfig) (string, error) {
	if cfg.GuardURL == "" {
		return "", errors.New("guard: GuardURL is required")
	}
	if cfg.ClientID == "" {
		return "", errors.New("guard: ClientID is required")
	}
	guardURL := strings.TrimRight(cfg.GuardURL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultLoginTimeout
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	authURL := cfg.AuthURL
	if authURL == "" {
		authURL = googleAuthURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = googleTokenURL
	}
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("guard: invalid ListenAddr: %w", err)
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", fmt.Errorf("guard: ListenAddr must be a loopback address, got %q", listenAddr)
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return "", fmt.Errorf("guard: listen for oauth callback: %w", err)
	}
	defer ln.Close()
	redirectURL := "http://" + ln.Addr().String() + "/callback"

	state, err := randomURLToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomURLToken()
	if err != nil {
		return "", err
	}

	resultCh := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Query().Get("state") != state {
			http.Error(w, "Invalid state", http.StatusBadRequest)
			select {
			case resultCh <- callbackResult{err: errors.New("guard: oauth state mismatch")}:
			default:
			}
			return
		}
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			writeClosePage(w, "Sign-in failed: "+errParam)
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("guard: google returned %s", errParam)}:
			default:
			}
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			select {
			case resultCh <- callbackResult{err: errors.New("guard: missing authorization code")}:
			default:
			}
			return
		}
		writeClosePage(w, "Signed in. You can close this window and return to the program.")
		select {
		case resultCh <- callbackResult{code: code}:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	query := url.Values{
		"client_id":             {cfg.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURL},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	consentURL := authURL + "?" + query.Encode()
	if err := openBrowser(cfg.OpenBrowser, consentURL); err != nil {
		fmt.Fprintf(os.Stderr, "Open this URL to sign in:\n%s\n", consentURL)
	}

	var result callbackResult
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	if result.err != nil {
		return "", result.err
	}

	form := url.Values{
		"client_id":     {cfg.ClientID},
		"code":          {result.code},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURL},
	}
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	idToken, err := exchangeGoogleCode(ctx, client, tokenURL, form)
	if err != nil {
		return "", err
	}
	return exchangeGuardToken(ctx, client, guardURL, idToken)
}

type callbackResult struct {
	code string
	err  error
}

func randomURLToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("guard: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func openBrowser(open func(string) error, authURL string) error {
	if open != nil {
		return open(authURL)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", authURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL)
	default:
		cmd = exec.Command("xdg-open", authURL)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func writeClosePage(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<!doctype html><title>guard sign-in</title><p>"+html.EscapeString(message)+"</p>")
}

func exchangeGoogleCode(ctx context.Context, client *http.Client, tokenURL string, form url.Values) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("guard: google token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("guard: google token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("guard: read google token response: %w", err)
	}
	var payload struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("guard: decode google token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || payload.Error != "" {
		return "", fmt.Errorf("guard: google token exchange failed (%s): %s %s", resp.Status, payload.Error, payload.ErrorDescription)
	}
	if payload.IDToken == "" {
		return "", errors.New("guard: google token response has no id_token; request the openid scope")
	}
	return payload.IDToken, nil
}

func exchangeGuardToken(ctx context.Context, client *http.Client, guardURL, idToken string) (string, error) {
	form := url.Values{
		"provider": {"google"},
		"id_token": {idToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, guardURL+TokenExchangePath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("guard: token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("guard: token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("guard: read token exchange response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("guard: token exchange failed (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("guard: decode token exchange response: %w", err)
	}
	if payload.Token == "" {
		return "", errors.New("guard: token exchange response has no token")
	}
	return payload.Token, nil
}
