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

mux.Handle("/private", a.Flow.RequireLogin(a.Validators)(handler))
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
| `GUARD_SESSION_KEY` | ECDSA P-256 key PEM, literal or file path | ephemeral (sessions reset on restart) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | provider disabled |
| `GOOGLE_CLIENT_SECRET` | Google client secret, literal or file path | public client (PKCE) |
| `AZURE_CLIENT_ID` | Microsoft OAuth client ID | provider disabled |
| `AZURE_CLIENT_SECRET` | Microsoft client secret, literal or file path | public client (PKCE) |
| `AZURE_TENANT_ID` | Microsoft tenant restriction | all tenants (`common`) |

On Google Cloud or Azure, the `GOOGLE_*`/`AZURE_*` secrets can point at the
mounted secret files; in docker-compose, at `/run/secrets/...` volumes.

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