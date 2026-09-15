package guard

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"
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

// SkipPaths runs mw for every request except those whose URL path is in the
// exact-match exempt list, which pass straight through to next. This lets one
// guard middleware protect all routes while keeping a pinned set of paths
// (like a sign-in flow's own routes) reachable without credentials:
//
//	mw := guard.SkipPaths(flow.PublicRoutes(), guard.RequireVerifiedEmail(validators))
func SkipPaths(paths []string, mw Middleware) Middleware {
	exempt := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		exempt[p] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		guarded := mw(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := exempt[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}
			guarded.ServeHTTP(w, r)
		})
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
				http.Error(w, "missing or invalid credentials", http.StatusUnauthorized)
				return
			}

			user, err := authenticateUser(r.Context(), token, validators)
			if err != nil {
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
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
			http.Error(w, "insufficient roles: requires one of "+strings.Join(required, ", "), http.StatusForbidden)
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
						http.Error(w, "insufficient roles: requires "+strings.Join(required, ", "), http.StatusForbidden)
						return
					}
				}
				next.ServeHTTP(w, r)
			})
	}
}

// EnrichFromStore replaces the roles on the authenticated user with the roles
// resolved from the given RoleStore at request time. This ensures the user's
// roles reflect the current state of the store rather than the (potentially
// stale) roles embedded in the token. On store errors the roles are cleared
// and the request continues (fail-open). Requires RequireVerifiedEmail (or
// equivalent) earlier in the chain.
func EnrichFromStore(store RoleStore) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				user := MustGetUserFromCtx(r.Context())
				roles, err := store.RolesByEmail(r.Context(), user.Email)
				if err != nil {
					slog.Error("enrich roles: store lookup failed", "email", user.Email, "error", err)
					user.Roles = []string{}
				} else {
					user.Roles = roles
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
				http.Error(w, "email not authorized", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
	}
}
