package guard

import (
	"context"
	"net/http"
)

// GetUserFromCtx returns the authenticated user stored in the context by
// RequireVerifiedEmail or OptionalAuth, and whether one is present.
func GetUserFromCtx(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userKey).(*User)
	return user, ok
}

// OptionalAuth authenticates the request when a valid credential is present,
// storing the user (and token) in the context, and otherwise passes the request
// through unauthenticated. Handlers can use GetUserFromCtx to branch on
// whether the visitor is signed in. Invalid credentials do not fail the
// request.
func OptionalAuth(validators []TokenValidator) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if token, err := getAuthToken(r); err == nil {
				if user, err := authenticateUser(ctx, token, validators); err == nil {
					ctx = context.WithValue(ctx, userKey, user)
					ctx = context.WithValue(ctx, tokenKey, token)
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
