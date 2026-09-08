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
google := bearer.NewGoogleTokenValidator("google-client-id")
microsoft := bearer.NewMicrosoftTokenValidator(tenantId, "microsoft-client-id")
```

- `NewGoogleTokenValidator` validates Google ID tokens for the given client ID.
- `NewMicrosoftTokenValidator(tenantId, clientId)` validates Microsoft Entra ID
  tokens. Use `"common"` as `tenantId` to accept users from any Entra ID tenant
  (multi-tenant), or a specific tenant ID to restrict to a single tenant.

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
