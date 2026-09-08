package signin

import (
	"net/http"
	"time"
)

type cookieOptions struct {
	name  string
	value string
	ttl   time.Duration
	clear bool
}

func (f *Flow) writeSessionCookie(w http.ResponseWriter, token string) {
	f.writeCookie(w, cookieOptions{name: f.cookieName, value: token, ttl: f.sessionTTL})
}

func (f *Flow) clearSessionCookie(w http.ResponseWriter) {
	f.writeCookie(w, cookieOptions{name: f.cookieName, clear: true})
}

func (f *Flow) writeStateCookie(w http.ResponseWriter, value string) {
	f.writeCookie(w, cookieOptions{name: stateCookieName, value: value, ttl: stateTTL})
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
	f.writeSessionCookie(w, token)
}

// ClearSessionCookie removes the session cookie.
func (f *Flow) ClearSessionCookie(w http.ResponseWriter) {
	f.clearSessionCookie(w)
}
