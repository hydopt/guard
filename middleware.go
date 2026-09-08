package bearer

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"slices"
)

type Middleware func(http.Handler) http.Handler

func Chain(ms ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for _, m := range slices.Backward(ms) {
			next = m(next)
		}
		return next
	}
}

type userCtxKey string

const userKey userCtxKey = "user"
const tokenKey userCtxKey = "token"

func MustGetUserFromCtx(ctx context.Context) *User {
	user, ok := ctx.Value(userKey).(*User)
	Assert(ok, "user must be part of context")
	return user
}

func MustGetTokenFromCtx(ctx context.Context) string {
	token, ok := ctx.Value(tokenKey).(string)
	Assert(ok, "token should be part of context")
	return token
}

func RequireVerifiedEmail(validators []TokenValidator) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				token, err := getAuthToken(r)
				if err != nil {
					http.Error(w, "Not authorized", http.StatusUnauthorized)
					return
				}

				user, err := authenticateUser(r.Context(), token, validators)
				if err != nil {
					http.Error(w, "Not authorized", http.StatusUnauthorized)
					return
				}

				ctx := context.WithValue(r.Context(), userKey, user)
				ctx = context.WithValue(ctx, tokenKey, token)
				next.ServeHTTP(w, r.WithContext(ctx))
			})
	}
}

func RequireMinimumRole[T cmp.Ordered](store RoleStore[T], minimumRole T) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				user := MustGetUserFromCtx(r.Context())
				role, err := store.RoleByEmail(r.Context(), user.Email)
				if err != nil || role < minimumRole {
					slog.Info("Insufficient privileges", "error", err, "role", role)
					http.Error(w, "Insufficient privileges", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
	}
}

func RequireWhiteListedEmail(whitelist []string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				user := MustGetUserFromCtx(r.Context())
				if !slices.Contains(whitelist, user.Email) {
					http.Error(w, "Email not in whitelist", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
	}
}
