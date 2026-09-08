package signin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type cookieOptions struct {
	name  string
	value string
	ttl   time.Duration
	clear bool
}

func (f *Flow) writeSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	f.writeCookie(w, cookieOptions{name: f.cookieName, value: token, ttl: ttl})
}

func (f *Flow) clearSessionCookie(w http.ResponseWriter) {
	f.writeCookie(w, cookieOptions{name: f.cookieName, clear: true})
}

func (f *Flow) writeStateCookie(w http.ResponseWriter, req loginRequest) {
	b, err := json.Marshal(req)
	if err != nil {
		panic(err) // loginRequest holds only JSON-safe fields
	}
	// base64url keeps the value within the bytes a browser will echo back.
	f.writeCookie(w, cookieOptions{name: stateCookieName, value: base64.RawURLEncoding.EncodeToString(b), ttl: stateTTL})
}

func (f *Flow) clearStateCookie(w http.ResponseWriter) {
	f.writeCookie(w, cookieOptions{name: stateCookieName, clear: true})
}

func (f *Flow) writeCookie(w http.ResponseWriter, o cookieOptions) {
	cookie := &http.Cookie{
		Name:     o.name,
		Path:     "/",
		HttpOnly: true,
		Secure:   f.secure,
		SameSite: http.SameSiteLaxMode,
		Value:    o.value,
	}
	if o.clear || o.ttl <= 0 {
		cookie.MaxAge = -1
	} else {
		cookie.MaxAge = int(o.ttl.Seconds())
	}
	http.SetCookie(w, cookie)
}

// SetSessionCookie stores token as the session cookie, authenticating
// subsequent requests for middlewares built on bearer.SessionCookieName.
func (f *Flow) SetSessionCookie(w http.ResponseWriter, token string) {
	f.writeSessionCookie(w, token, f.sessionTTL)
}

// ClearSessionCookie removes the session cookie.
func (f *Flow) ClearSessionCookie(w http.ResponseWriter) {
	f.clearSessionCookie(w)
}

// sessionCookieTTL clamps the configured session TTL so the cookie never
// outlives the ID token it stores. Fallback to sessionTTL if the token's exp
// cannot be read.
func sessionCookieTTL(sessionTTL time.Duration, idToken string) time.Duration {
	exp, ok := idTokenExpiry(idToken)
	if !ok {
		return sessionTTL
	}
	remaining := time.Until(exp)
	if remaining <= 0 {
		return sessionTTL
	}
	if remaining < sessionTTL {
		return remaining
	}
	return sessionTTL
}

// idTokenExpiry reads the "exp" claim from an unverified JWT. Safe to inspect
// without verification: the token is validated separately before it reaches
// the cookie.
func idTokenExpiry(idToken string) (time.Time, bool) {
	payload, ok := decodeIDTokenPayload(idToken)
	if !ok {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// idTokenNonce reads the "nonce" claim from an unverified JWT. Safe to inspect
// without verification: the validator has already verified the signature.
func idTokenNonce(idToken string) (string, bool) {
	payload, ok := decodeIDTokenPayload(idToken)
	if !ok {
		return "", false
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	return claims.Nonce, claims.Nonce != ""
}

func decodeIDTokenPayload(idToken string) ([]byte, bool) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	return payload, true
}
