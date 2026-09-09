package guard

import (
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

// RequireAnyRole denies the request unless the authenticated user holds at
// least one of the given roles. Roles come from the guard token's claims, so
// no role store is consulted on the request path. Requires RequireVerifiedEmail
// (or equivalent) earlier in the chain.
func RequireAnyRole(required ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				user := MustGetUserFromCtx(r.Context())
				for _, want := range required {
					if slices.Contains(user.Roles, want) {
						next.ServeHTTP(w, r)
						return
					}
				}
				slog.Info("Insufficient privileges", "email", user.Email)
				http.Error(w, "Forbidden", http.StatusForbidden)
			})
	}
}

// RequireAllRoles denies the request unless the authenticated user holds every
// given role. Roles come from the guard token's claims, so no role store is
// consulted on the request path. Requires RequireVerifiedEmail (or equivalent)
// earlier in the chain.
func RequireAllRoles(required ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				user := MustGetUserFromCtx(r.Context())
				for _, want := range required {
					if !slices.Contains(user.Roles, want) {
						slog.Info("Insufficient privileges", "email", user.Email)
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
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
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
	}
}
