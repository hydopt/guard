# guard

Auth and authorization for Go HTTP services: sign users in with Google,
Microsoft, or email/password, mint your own session tokens, and protect
handlers with composable middleware.

`guard` is your own OAuth-style issuer. Every successful sign-in produces a
**guard token** signed by a key you control, with your app's origin as its
`iss`, served at `/.well-known/jwks.json`. Any service can validate these
tokens against your JWKS — no shared secrets, no shared state. Self-validation
is always on: middleware only accepts guard tokens, never raw provider ID
tokens.

## Installation

```sh
go get github.com/hydopt/guard
```

## Quick start

`auth.Setup` reads everything from the environment, so one call is all it
takes:

```go
import "github.com/hydopt/guard/auth"

a, err := auth.Setup(mux) // env-configured: providers, origin, signing key
if err != nil { /* handle */ }

mux.Handle("/", a.OptionalAuth()(handler))     // pass through, user optional
mux.Handle("/private", a.RequireLogin()(handler)) // redirects to /signin when needed
```

It registers the sign-in page (`/signin`), the provider routes, logout, and the
guard JWKS endpoint. To override individual pieces, hand it options — they
always beat the environment:

```go
a, err := auth.Setup(mux,
    auth.Issuer("https://app.example.com"), // beats GUARD_ORIGIN
    auth.WithSessionKey(pemBytes),          // beats GUARD_SESSION_KEY
    auth.Google("client-id"),               // beats GOOGLE_CLIENT_ID
    auth.WithTenant("my-tenant-guid"),      // beats AZURE_TENANT_ID
    auth.EmailPassword(store),              // add email/password login
    auth.WithRoleStore(roleStore),          // roles become token claims
)
```

## Environment variables

Secrets follow the value-or-path rule: the value is either the secret itself
or the path of a file containing it (cloud and docker-compose mount secrets as
files). Missing values fall back to their default.

| Variable | Purpose | Default |
| --- | --- | --- |
| `GUARD_ORIGIN` | issuer origin (`iss` claim, JWKS base) | required, or `auth.Issuer(...)` |
| `GUARD_SESSION_KEY` | ECDSA P-256 key PEM, literal or file path | random per process when unset |
| `GUARD_ROLES` | role assignments, one `<email>;<role1>;<role2>;...` per line | no roles |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | provider disabled |
| `GOOGLE_CLIENT_SECRET` | Google client secret, literal or file path | public client (PKCE) |
| `AZURE_CLIENT_ID` | Microsoft OAuth client ID | provider disabled |
| `AZURE_CLIENT_SECRET` | Microsoft client secret, literal or file path | public client (PKCE) |
| `AZURE_TENANT_ID` | Microsoft tenant restriction | all tenants (`common`) |

On Google Cloud or Azure, the `GOOGLE_*`/`AZURE_*` secrets can point at the
mounted secret files; in docker-compose, at `/run/secrets/...` volumes.

### Session keys and serverless

`GUARD_SESSION_KEY` is only ephemeral when it is unset: every process then
generates its own in-memory signing key. That is fine for a single process,
but breaks multi-instance or serverless deployments, because each instance
signs with a different key and serves its own JWKS — tokens minted by one
instance fail validation on another. Point `GUARD_SESSION_KEY` at a stable key
shared by the deployment (`make gen-key`, then keep it in a secret manager or
mounted secret file). A consistent key also keeps sessions valid across
restarts and cold starts.

`GUARD_ROLES` auto-plugs a role store into `auth.Setup`, so zero-config role
claims work out of the box:

```sh
GUARD_ROLES="alice@example.com;admin;user
bob@example.com;user"
```

## Store implementations

guard ships a few stores for the `CredentialStore` and `RoleStore` interfaces:

- `guard.InMemoryCredentialStore` and `guard.InMemoryRoleStore` — static maps,
  ideal for tests and demos.
- `guard.NewEnvRoleStore()` — role assignments from `GUARD_ROLES`.
- `github.com/hydopt/guard/firestore` — an optional, separately versioned
  module: one Firestore collection of user documents (`password_hash` bcrypt
  hashes + `roles`) implements both interfaces. It only pulls in
  `cloud.google.com/go/firestore` when you import it:

```go
import "github.com/hydopt/guard/firestore"

store := firestore.NewStore(client, "users")
a, err := auth.Setup(mux,
    auth.EmailPassword(store),
    auth.WithRoleStore(store),
)
```

- `github.com/hydopt/guard/sqlstore` — an optional, separately versioned
  module built on stdlib `database/sql` with a normalized
  `users`/`user_roles` schema, so it works with any driver (postgres, mysql,
  sqlite, ...). It pulls in no driver itself:

```go
import "github.com/hydopt/guard/sqlstore"

db, _ := sql.Open("postgres", connStr)
store := sqlstore.NewStore(db, "users", "user_roles")
if err := store.Migrate(ctx); err != nil { /* handle */ }
a, err := auth.Setup(mux,
    auth.EmailPassword(store),
    auth.WithRoleStore(store),
)
```

## Validation and middleware

Downstream services validate guard tokens against your JWKS:

```go
validator, err := guard.NewValidatorFromIssuerURL(ctx, "https://app.example.com")
user, err := validator.ValidateToken(ctx, bearerToken) // *guard.User
```

Compose middleware to protect routes:

```go
handler := guard.Chain(
    guard.RequireVerifiedEmail(validators),
    guard.RequireAnyRole("admin"),     // roles come from token claims
    guard.RequireWhiteListedEmail(whitelist),
)(mux)
```

### Protecting an entire tree

Want every route behind the same middleware, including the sign-in flow itself?
`auth.Setup` registers the flow on the mux you hand it, so serve that mux.
`Flow.RequireLogin` (and `Auth.RequireLogin`) already lets the flow's own
routes through, so the simplest whole-app protection is wrapping the whole mux:

```go
mux := http.NewServeMux()
a, _ := auth.Setup(mux)
mux.Handle("/", a.OptionalAuth()(home))
a.RequireLogin()(mux)                  // /signin, /auth/*, logout stay reachable
```

For any *other* middleware (say a raw `guard.RequireVerifiedEmail` chain), keep
the flow's routes open with `guard.SkipPaths` and the exact route list:

```go
mw := guard.SkipPaths(a.PublicRoutes(), guard.RequireVerifiedEmail(validators))
handler := mw(mux)                     // only the sign-in flow is unguarded
```

`PublicRoutes()` lists the exact-match paths the flow owns: `/signin`, each
provider's start and callback route, logout, and local endpoints (like the
email/password login and token routes). The flow keeps working no matter which
`guard.Middleware` protects the `?next=` return target.

Further APIs (signin, guard.Issuer, credential stores, components) are
documented in the package docs.

## Examples

Runnable examples live in [`example/`](example/). Each one is exercised by the
CI pipeline's hurl integration tests.

[`example/basic-auth`](example/basic-auth/) wires a self-hosted
email/password issuer (sign-in page, session minting, role middleware) into a
demo app in a single `auth.Setup` call:

```sh
make -C example/basic-auth run    # launch the demo (localhost:8080)
make -C example/basic-auth test   # launch + run the hurl suite
```

Sign in with `alice@example.com / password` (roles: admin, user) or
`bob@example.com / password` (roles: user).

## License

MIT