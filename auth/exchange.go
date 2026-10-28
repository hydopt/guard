package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hydopt/guard"
)

// handleTokenExchange trades a provider ID token for a guard token, so local
// programs (CLIs, desktop apps) can sign in through the browser and then call
// guard-protected services with a Bearer token. The provider token is validated
// at the sign-in boundary, exactly like the browser callback; the minted guard
// token carries the roles resolved from the role store.
//
//	POST /auth/token
//	Content-Type: application/x-www-form-urlencoded
//
//	provider=google&id_token=<provider id token>
func (a *Auth) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	provider := strings.TrimSpace(r.Form.Get("provider"))
	idToken := strings.TrimSpace(r.Form.Get("id_token"))
	if provider == "" || idToken == "" {
		http.Error(w, "provider and id_token are required", http.StatusBadRequest)
		return
	}
	validator, ok := a.exchange[provider]
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}
	user, err := validator.ValidateToken(r.Context(), idToken)
	if err != nil {
		slog.Info("token exchange: provider validation failed", "provider", provider, "error", err)
		http.Error(w, "invalid provider token", http.StatusUnauthorized)
		return
	}

	ttl := a.sessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	opts := []guard.TokenOption{guard.WithProvider(provider)}
	if len(user.Roles) > 0 {
		opts = append(opts, guard.WithRoles(user.Roles))
	}
	token, err := a.Issuer.SignToken(user.Email, ttl, opts...)
	if err != nil {
		slog.Error("token exchange: signing failed", "provider", provider, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": int(ttl.Seconds()),
	})
}
