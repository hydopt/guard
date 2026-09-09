# guard

Auth and authorization for Go HTTP services: sign users in with Google,
Microsoft, or a self-hosted email/password issuer, mint your own session
tokens, and protect handlers with composable middleware.

Instead of handing downstream services third-party ID tokens, `guard` acts as
your own OAuth-style issuer: every successful sign-in produces a **guard
token** signed by a key you control, with your app's origin as its `iss`. Any
service can validate these tokens against your JWKS — no shared secrets, no
shared state.

## Installation

```sh
go get github.com/hydopt/guard
```

## Quick start

Wire the guard issuer, the sign-in providers, and the auth routes into your mux
with one call:

```go
import "github.com/hydopt/guard/auth"

a, err := auth.Setup(mux,
    auth.Issuer("https://app.example.com"),
    auth.WithSessionKey(sessionKeyPEM), // stable ECDSA signing key
    auth.Google("google-client-id"),
    auth.Microsoft("microsoft-client-id"),
    auth.EmailPassword(store), // optional email/password login
    auth.WithRoleStore(roleStore), // optional: roles → token claims
)
if err != nil { /* handle — validator construction performs discovery */ }

mux.Handle("/private", a.Flow.RequireLogin(a.Validators)(handler))
```

`auth.Setup` registers the sign-in page (`/signin`), the provider routes
(`/auth/{provider}` and their callbacks), logout (`/auth/logout`), and the
guard JWKS endpoint (`/.well-known/jwks.json`). Defaults: Microsoft accepts any
tenant (`"common"`), sessions last an hour, and cookies are not marked `Secure`
(enter production with `auth.WithSecure(true)`).

**About the client secret:** Google and Microsoft register server-side ("web
application") clients as *confidential* clients that must authenticate at the
token exchange with a `client_secret`. `Setup` picks the secret up from
`GOOGLE_CLIENT_SECRET` / `AZURE_CLIENT_SECRET` (or an explicit
`auth.WithGoogleSecret` / `auth.WithMicrosoftSecret`). If you register the
clients as *public* (SPA/desktop/native types) instead, no secret is needed:
the PKCE we already send protects the code exchange, and `Setup` simply omits
the `client_secret`. Either registration works — just make the console match
the environment you choose.

Other options: `auth.WithTenant(tenantGUID)` to pin Microsoft to a single
tenant, `auth.WithSessionTTL(...)`, and `auth.WithValidator(name, validator)`
to swap in custom sign-in validators (e.g. national clouds).

## Guard tokens & downstream validation

Every sign-in path (Google, Microsoft, email/password) ends with the same step:
the issuer mints a guard token signed by your ECDSA P-256 key, listing your
origin as `iss`. It carries the user's email, the sign-in provider, and any
roles resolved from the role store at mint time. Middleware and `Bearer`
requests only accept guard tokens by default — provider tokens are consumed at
the sign-in boundary and never forwarded.

Downstream services validate guard tokens against your JWKS, either by
discovering it from your origin, or by holding a copy of the public key:

```go
// Any other service of yours:
validator, err := guard.NewValidatorFromIssuerURL(ctx, "https://app.example.com")
user, err := validator.ValidateToken(ctx, bearerToken) // *guard.User

// Or pin the public key PEM directly:
validator, err := guard.NewIssuer(guard.IssuerConfig{
    Issuer:       "https://app.example.com",
    PublicKeyPEM: pemBytes, // exported once via issuer.PublicKeyPEM()
})
```

`NewIssuer` likewise signs tokens programmatically, e.g. for machine-to-machine
service accounts:

```go
issuer, err := guard.NewIssuer(guard.IssuerConfig{Issuer: "https://app.example.com"})
token, err := issuer.SignToken("billing@example.com", time.Hour, guard.WithRoles([]string{"admin"}))
```

**Signing keys:** `Issuer()` auto-generates an in-memory ECDSA key when no
`WithSessionKey` is configured and warns about it — sessions reset on restart.
In production, configure a stable key (e.g. read a PEM file at startup) so
tokens survive restarts and match the JWKS you distribute. The public half is
served at `{origin}/.well-known/jwks.json`.

**Issuer/validator modes:**

- `NewIssuer(IssuerConfig)` — owner of a signing private key (or a read-only
  validator given only the public key PEM).
- `NewValidatorFromIssuerURL(ctx, origin)` — discovers and caches the JWKS from
  an origin, like a downstream service would.
- `NewValidatorFromJWKS(keyset, issuer)` — validates against a fixed key set.

## Usage

### Sign-in flow

The `signin` package provides a server-side OAuth2 flow: redirect to the
provider, exchange the code, validate the ID token, mint a guard token, and
store it as the session cookie.

```go
import (
    "github.com/hydopt/guard"
    "github.com/hydopt/guard/signin"
    googleoauth "golang.org/x/oauth2/google"
    "golang.org/x/oauth2/endpoints"
)

issuer, err := guard.NewIssuer(guard.IssuerConfig{Issuer: "https://app.example.com"})
google, err := guard.NewGoogleTokenValidator("google-client-id")
microsoft, err := guard.NewMicrosoftTokenValidator("common", "microsoft-client-id")

flow, err := signin.New(signin.Config{
    Secure: true, // set in production
    Issuer: issuer, // mint guard sessions; omit to store provider tokens instead
    Providers: []signin.Provider{
        {
            Name:         "google",
            Label:        "Google",
            ClientID:     "...",
            ClientSecret: "...",
            Endpoint:     googleoauth.Endpoint,
            Validator:    google, // validates Google ID tokens at sign-in only
        },
        {
            Name:         "microsoft",
            Label:        "Microsoft",
            ClientID:     "...",
            ClientSecret: "...",
            Endpoint:     endpoints.AzureAD("common"),
            Validator:    microsoft,
        },
    },
})
```

Wire it up on a `http.ServeMux`:

```go
mux := http.NewServeMux()
flow.Register(mux) // /signin, /auth/{provider}, /auth/{provider}/callback, /auth/logout

protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user := guard.MustGetUserFromCtx(r.Context())
    // user.Email, user.Roles, user.Provider, user.Claims
})
mux.Handle("/private", flow.RequireLogin([]guard.TokenValidator{issuer})(protected))
```

`RequireLogin` redirects signed-out GET/HEAD requests to the sign-in page
(returning them to the original path after login) and otherwise behaves like
`RequireVerifiedEmail`. Use `RequireVerifiedEmail` directly for strict-401
endpoints, e.g. APIs.

Routes:

| Route | Method | Behavior |
| --- | --- | --- |
| `/signin` | GET | Renders the sign-in page (`?next=` is honored) |
| `/auth/{provider}` | GET | Redirects to the provider |
| `/auth/{provider}/callback` | GET | Exchanges the code, validates the ID token, mints a guard token, sets the session cookie, redirects to `next` |
| `/auth/logout` | POST | Clears the session cookie |

Callbacks also support `?mode=token`, returning
`{"token": ..., "token_type": "Bearer", "expires_in": ...}` as JSON instead of
setting a cookie and redirecting. The session cookie is only written in the
standard (redirect) flow.

Notes:

- Register the callback URL (e.g. `https://example.com/auth/google/callback`)
  in each provider's console. By default the callback URL is derived from the
  incoming request, honoring `X-Forwarded-Proto` / `X-Forwarded-Host` so TLS
  termination behind a reverse proxy works; override with `Provider.RedirectURL`
  when you need an exact match.
- The OAuth start uses PKCE (S256) and an OIDC `nonce`; the state cookie —
  which holds the CSRF state, the same-origin `next` target, the code verifier,
  and the nonce — is short-lived and http-only. `next` must be a same-origin
  path to prevent open redirects. The callback re-validates that the ID token
  echoes the nonce, binding the token to this sign-in.
- When `Config.Issuer` is set, roles for the signed-in user are resolved from
  the issuer's role store and embedded as `roles` claims at mint time. With a
  provider that already issues guard tokens itself (e.g.
  `signin.NewBasicAuthProvider`), the callback stores that token as-is.
- The session cookie is read by `RequireVerifiedEmail` via
  `guard.SessionCookieName`. Set `Config.Secure = true` in production.
- `/auth/logout` only clears the session when the request actually carries one,
  so cross-site logout CSRF (a third-party POST that would otherwise make the
  server clear the cookie) is ineffective.
- There is no refresh-token plumbing: sessions last `SessionTTL` (1 hour by
  default) and then the user signs in again. This keeps the design stateless
  and the token forwardable between services.

### Email/password login

`auth.EmailPassword(store)` mounts a self-contained login form backed by a
credential store and mints guard tokens from the same issuer:

```go
store := guard.NewInMemoryCredentialStore(map[string]string{
    "alice@example.com": "s3cret", // bcrypt-hashed by the store
})
a, err := auth.Setup(mux, auth.Issuer("https://app.example.com"), auth.EmailPassword(store))
```

Credentials are stored as bcrypt hashes (`Authenticate` compares against the
hash and never persists the plaintext). For full control, build the provider
directly with `signin.NewBasicAuthProvider(issuer, store)` and register its
local OAuth2 endpoints on your own mux; `Authorization`-code flow, PKCE, and
single-use codes are enforced. Programmatic issuance for this path:

```go
token, err := a.Issuer.SignToken("alice@example.com", time.Hour)
```

### Validators

A `TokenValidator` verifies a bearer token and returns a [`User`](#types).

```go
google, err := guard.NewGoogleTokenValidator("google-client-id")
if err != nil { /* handle */ }
microsoft, err := guard.NewMicrosoftTokenValidator(tenantId, "microsoft-client-id")
```

- `NewGoogleTokenValidator` validates Google ID tokens for the given client ID.
- `NewMicrosoftTokenValidator(tenantId, clientId)` validates Microsoft Entra ID
  tokens. Pass a tenant ID to restrict sign-in to a single tenant: the tenant
  GUID is recommended (a verified domain such as `contoso.onmicrosoft.com`
  also works and is resolved to its GUID during discovery). Or use a
  tenant-independent mode for multi-tenant apps:
  - `"common"` — any organizational directory plus personal Microsoft accounts
  - `"organizations"` — any organizational directory (work/school accounts)
  - `"consumers"` — personal Microsoft accounts only

  Entra ID puts the actual tenant in every token's `iss` claim (and its
  metadata sometimes reports the `{tenantid}` placeholder), so exact-issuer
  matching is unreliable. All modes verify the signature and enforce the tenant
  chain of trust: a GUID `tid` claim whose issuer is
  `https://login.microsoftonline.com/{tid}/v2.0`. Single-tenant mode also pins
  `tid` to the configured tenant, which rejects B2B guest users whose home
  tenant differs. If a domain cannot be resolved to a GUID (placeholder
  issuer), construction fails with a hint to configure the GUID explicitly.

Multiple validators can be supplied; they are tried in order until one succeeds.
Provider validators are meant for the sign-in boundary — for middleware,
`auth.Validators` provides your guard issuer.

### Middleware

Middleware is composed with `Chain` and wrapped around an `http.Handler`
(e.g. a `http.ServeMux`). Middleware in the chain runs left to right, outermost
first.

```go
mux := http.NewServeMux()

handler := guard.Chain(
    guard.RequireVerifiedEmail(validators),
    guard.RequireAnyRole("admin"),
    guard.RequireAllRoles("tenant-a", "viewer"),
    guard.RequireWhiteListedEmail(whitelist),
)(mux)
```

- `RequireVerifiedEmail` authenticates the request and stores the user in the
  request context. It must come first in the chain.
- `RequireAnyRole(required...)` / `RequireAllRoles(required...)` grant access
  based on the `roles` claims carried by the guard token, so no role store is
  consulted on the request path. `RequireWhiteListedEmail` reads the
  authenticated user from the context. All three must be placed after
  `RequireVerifiedEmail`.

Authentication sources, in order of priority:
1. `Authorization: Bearer <token>` header (any other scheme is rejected)
2. the session cookie (`guard.SessionCookieName`, default `"session"`)

Authenticated requests also expose the raw credential in the context,
retrievable with `MustGetTokenFromCtx`. The authenticated user is retrievable
with `MustGetUserFromCtx`. `RequireAnyRole`, `RequireAllRoles`, and
`RequireWhiteListedEmail` reject with 403 (not 401, which is reserved for
missing/invalid credentials).

Every `User` also carries the full ID token claim set (`User.Claims`, e.g.
Microsoft `groups`/`roles` or custom claims). It is excluded from JSON
serialization so token internals do not leak into API responses by default.

For public pages that show different content (e.g. a user menu) when signed in,
use `OptionalAuth`, which authenticates when a valid credential is present and
passes everything else through unauthenticated:

```go
handler := guard.OptionalAuth(validators)(next)
if user, ok := guard.GetUserFromCtx(r.Context()); ok {
    // visitor is signed in
}
```

## Types

```go
type TokenValidator interface {
    ValidateToken(ctx context.Context, token string) (*User, error)
}

type User struct {
    Id            string
    Email         string
    VerifiedEmail bool
    Sub           string
    Roles         []string // resolved from the role store at sign-in
    Provider      string   // "google", "microsoft", ...
    Claims        map[string]any // raw ID token claims
}

type Middleware func(http.Handler) http.Handler
```

## License

MIT