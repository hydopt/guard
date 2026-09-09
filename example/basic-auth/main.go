// Command basic-auth is a runnable demo of the guard library.
//
// It wires up the whole self-hosted email/password auth stack in one
// auth.Setup call: sign-in page, local OIDC issuer that mints signed session
// tokens, role claims, and route middleware. All page HTML lives in the
// package (the sign-in page, provider routes, logout, and JWKS are registered
// by auth.Setup); the demo only serves its own content as plain text.
//
// The configuration env vars from the root README still apply; here
// GUARD_ORIGIN is conveniently defaulted to the local origin when unset.
//
// Run it with:
//
//	make run
//
// then open http://localhost:8080 and sign in with
// alice@example.com / password (roles: admin, user) or
// bob@example.com / password (roles: user).
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hydopt/guard"
	"github.com/hydopt/guard/auth"
)

const defaultPort = "8080"

func writeText(w http.ResponseWriter, status int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		log.Printf("write: %v", err)
	}
}

func renderUser(w http.ResponseWriter, user *guard.User, extra string) {
	writeText(w, http.StatusOK, "Signed in as %s\nRoles: %s\nProvider: %s\n\n%s",
		user.Email, strings.Join(user.Roles, ", "), user.Provider, extra)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if user, ok := guard.GetUserFromCtx(r.Context()); ok {
		renderUser(w, user, "Protected:\n/private\n/private/admin\n\nLog out: POST /auth/logout")
		return
	}
	writeText(w, http.StatusOK, "Not signed in.\n\nSign in: /signin\nProtected: /private, /private/admin")
}

func handlePrivate(w http.ResponseWriter, r *http.Request) {
	renderUser(w, guard.MustGetUserFromCtx(r.Context()), "Admin-only: /private/admin")
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	renderUser(w, guard.MustGetUserFromCtx(r.Context()), "You reached the admin-only page.")
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	if os.Getenv("GUARD_ORIGIN") == "" {
		os.Setenv("GUARD_ORIGIN", "http://localhost:"+port)
	}

	creds := guard.NewInMemoryCredentialStore(map[string]string{
		"alice@example.com": "password",
		"bob@example.com":   "password",
	})

	roles := guard.InMemoryRoleStore{
		"alice@example.com": {"admin", "user"},
		"bob@example.com":   {"user"},
	}

	mux := http.NewServeMux()
	a, err := auth.Setup(mux,
		auth.EmailPassword(creds),
		auth.WithRoleStore(roles),
	)
	if err != nil {
		log.Fatal(err)
	}

	// authMw: every authenticated route. Guardians of a chain compose, so the
	// admin route extends the same middleware instead of re-declaring it.
	authMw := guard.Chain(
		a.Flow.RequireLogin(a.Validators),
		guard.RequireVerifiedEmail(a.Validators),
	)
	adminMw := guard.Chain(authMw, guard.RequireAnyRole("admin"))

	mux.Handle("/", guard.OptionalAuth(a.Validators)(http.HandlerFunc(handleHome)))
	mux.Handle("/private", authMw(http.HandlerFunc(handlePrivate)))
	mux.Handle("/private/admin", adminMw(http.HandlerFunc(handleAdmin)))

	log.Printf("listening on :%s (origin %s)", port, os.Getenv("GUARD_ORIGIN"))
	log.Println("sign in with alice@example.com / password (admin) or bob@example.com / password")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}
