# bearer

Small library to validate bearer tokens (JWTs issued by Google and Microsoft
Entra ID) and protect HTTP handlers with composable middleware.

## Installation

```sh
go get github.com/hydopt/bearer
```

## Usage

### Validators

A `TokenValidator` verifies a bearer token and returns a [`User`](#types).

```go
google, err := bearer.NewGoogleTokenValidator("google-client-id")
if err != nil { /* handle */ }
microsoft, err := bearer.NewMicrosoftTokenValidator(tenantId, "microsoft-client-id")
```

- `NewGoogleTokenValidator` validates Google ID tokens for the given client ID.
- `NewMicrosoftTokenValidator(tenantId, clientId)` validates Microsoft Entra ID
  tokens. Pass a tenant ID (a GUID or verified domain such as
  `contoso.onmicrosoft.com`) to restrict sign-in to a single tenant, or use a
  tenant-independent mode for multi-tenant apps:
  - `"common"` — any organizational directory plus personal Microsoft accounts
  - `"organizations"` — any organizational directory (work/school accounts)
  - `"consumers"` — personal Microsoft accounts only

  Because Entra ID puts the tenant in every token's `iss` claim, multi-tenant
  modes validate the signature against the tenant-independent keys endpoint and
  enforce the tenant chain of trust (`tid` claim + matching `iss`) instead of
  exact-issuer matching.

Multiple validators can be supplied; they are tried in order until one succeeds.

### Middleware

Middleware is composed with `Chain` and wrapped around an `http.Handler`
(e.g. a `http.ServeMux`). Middleware in the chain runs left to right, outermost
first.

```go
mux := http.NewServeMux()

handler := bearer.Chain(
    bearer.RequireVerifiedEmail(validators),
    bearer.RequireMinimumRole(store, role),
    bearer.RequireWhiteListedEmail(whitelist),
)(mux)
```

- `RequireVerifiedEmail` authenticates the request and stores the user in the
  request context. It must come first in the chain.
- `RequireMinimumRole` / `RequireWhiteListedEmail` read the authenticated user
  from the context and must be placed after `RequireVerifiedEmail`.

Authentication sources, in order of priority:
1. `Authorization: Bearer <token>` header
2. the session cookie (`bearer.SessionCookieName`, default `"session"`)

Requests that authenticate via the header also store the raw token in the
context, retrievable with `MustGetTokenFromCtx`. The authenticated user is
retrievable with `MustGetUserFromCtx`.

For public pages that show different content (e.g. a user menu) when signed in,
use `OptionalAuth`, which authenticates when a valid credential is present and
passes everything else through unauthenticated:

```go
handler := bearer.OptionalAuth(validators)(next)
if user, ok := bearer.GetUserFromCtx(r.Context()); ok {
    // visitor is signed in
}
```

Multiple validators are tried in order until one succeeds, so list specific
providers first.

### Sign-in flow

The `signin` package provides a server-side OAuth2 flow for Google and
Microsoft: redirect to the provider, exchange the code, validate the ID token
with your existing validator, and store it as the session cookie.

```go
import (
    "github.com/hydopt/bearer"
    "github.com/hydopt/bearer/signin"
    googleoauth "golang.org/x/oauth2/google"
    "golang.org/x/oauth2/endpoints"
)

google, err := bearer.NewGoogleTokenValidator("google-client-id")
microsoft, err := bearer.NewMicrosoftTokenValidator("common", "microsoft-client-id")

flow, err := signin.New(signin.Config{
    Secure: true, // set in production
    Providers: []signin.Provider{
        {
            Name:         "google",
            Label:        "Google",
            ClientID:     "...",
            ClientSecret: "...",
            Endpoint:     googleoauth.Endpoint,
            Validator:    google,
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
validators := []bearer.TokenValidator{google, microsoft}
mux := http.NewServeMux()
flow.Register(mux) // /signin, /auth/{provider}, /auth/{provider}/callback, /auth/logout

protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user := bearer.MustGetUserFromCtx(r.Context())
    // ...
})
mux.Handle("/private", flow.RequireLogin(validators)(protected))
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
| `/auth/{provider}/callback` | GET | Exchanges the code, validates the ID token, sets the session cookie, redirects to `next` |
| `/auth/logout` | POST | Clears the session cookie |

Callbacks also support `?mode=token`, returning
`{"token": ..., "token_type": "Bearer", "expires_in": ...}` as JSON instead of
setting a cookie and redirecting. The session cookie is only written in the
standard (redirect) flow.

Notes:

- Register the callback URL (e.g. `https://example.com/auth/google/callback`)
  in each provider's console. By default the callback URL is derived from the
  incoming request; override with `Provider.RedirectURL` when you need an exact
  match.
- The state is kept in a short-lived, http-only cookie to prevent login CSRF;
  `next` must be a same-origin path to prevent open redirects.
- The session cookie holds the provider ID token and is read by
  `RequireVerifiedEmail` via `bearer.SessionCookieName`. Set
  `Config.Secure = true` in production.
- The cookie never outlives the ID token it stores: its `Max-Age` is clamped to
  the token's `exp` claim (at most `SessionTTL`).
- There is no refresh-token plumbing: sessions last as long as the ID token
  (≈ 1 hour by default, tune `SessionTTL` down but not beyond the token's
  expiry) and then the user signs in again. This keeps the design stateless
  and the token forwardable between services.

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
}

type Middleware func(http.Handler) http.Handler
```

## License

MIT
