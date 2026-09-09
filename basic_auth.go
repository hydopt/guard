package guard

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var (
	_ TokenValidator = (*Issuer)(nil)
	_ TokenMinter    = (*Issuer)(nil)

	ErrNoPrivateKey  = errors.New("no private key available for signing")
	ErrNoPublicKey   = errors.New("no public key available for validation")
	ErrNoIssuerFound = errors.New("no signing key found in JWKS")
)

// JWKSPath is the discovery route where a guard token issuer publishes its
// signing keys. It matches the OIDC-conventional well-known location.
const JWKSPath = "/.well-known/jwks.json"

// TokenMinter issues guard session tokens. Packages that only need to mint
// (e.g. the sign-in flow) depend on this narrow interface rather than the
// concrete *Issuer.
type TokenMinter interface {
	SignToken(email string, ttl time.Duration, opts ...TokenOption) (string, error)
}

// IssuerConfig configures an Issuer.
type IssuerConfig struct {
	// PrivateKeyPEM is a PEM-encoded EC (P-256) private key. When set, the
	// issuer can both sign and validate tokens. Leave empty and supply
	// PublicKeyPEM to validate only, or leave both empty to auto-generate a
	// key pair (issuer mode).
	PrivateKeyPEM []byte
	// PublicKeyPEM is a PEM-encoded EC public key used for validation. If
	// PrivateKeyPEM is also set, it takes precedence.
	PublicKeyPEM []byte
	// Issuer is the iss claim written into signed tokens, and the base URL for
	// the /.well-known/jwks.json discovery endpoint. Leave empty when the
	// issuer is unknown (e.g. a plain JWKS-derived validator).
	Issuer string
	// RoleStore resolves roles at mint time so they ride along as claims and
	// downstream services can authorize without contacting the store. SignToken
	// consults it unless the caller passes WithRoles explicitly.
	RoleStore RoleStore
}

// Issuer signs and/or validates guard session tokens. It is an ECDSA P-256
// (ES256) issuer: the app signs with a private key, and any downstream service
// can validate with the corresponding public key fetched from the issuer's
// JWKS endpoint. No shared secret is needed.
type Issuer struct {
	privateKey *ecdsa.PrivateKey // nil for validation-only issuers
	publicKey  *ecdsa.PublicKey
	signer     jose.Signer // nil for validation-only issuers
	kid        string
	issuer     string
	roleStore  RoleStore
}

// NewIssuer creates an issuer from explicit keys. With a private key it can
// sign and validate; with only a public key it validates. With neither, it
// generates a fresh ECDSA P-256 key pair.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	v := &Issuer{issuer: cfg.Issuer, roleStore: cfg.RoleStore}

	switch {
	case len(cfg.PrivateKeyPEM) > 0:
		priv, err := parseECPrivateKeyPEM(cfg.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("issuer: invalid private key: %w", err)
		}
		if err := v.setPrivateKey(priv); err != nil {
			return nil, err
		}
	case len(cfg.PublicKeyPEM) > 0:
		pub, err := parseECPublicKeyPEM(cfg.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("issuer: invalid public key: %w", err)
		}
		if err := v.setPublicKey(pub); err != nil {
			return nil, err
		}
	default:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("issuer: key generation failed: %w", err)
		}
		if err := v.setPrivateKey(priv); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// NewValidatorFromIssuerURL builds a validation-only issuer by fetching
// {issuer}/.well-known/jwks.json. The returned issuer enforces that tokens
// carry the given issuer claim.
func NewValidatorFromIssuerURL(ctx context.Context, issuerURL string) (*Issuer, error) {
	v, err := NewValidatorFromJWKS(ctx, issuerURL+JWKSPath)
	if err != nil {
		return nil, err
	}
	v.issuer = issuerURL
	return v, nil
}

// NewValidatorFromJWKS builds a validation-only issuer from an explicit JWKS
// endpoint. The first EC signing key in the set is used.
func NewValidatorFromJWKS(ctx context.Context, jwksURL string) (*Issuer, error) {
	keyset, err := fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("issuer: fetch jwks: %w", err)
	}
	for _, k := range keyset.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, ok := k.Key.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		return NewIssuer(IssuerConfig{
			PublicKeyPEM: mustECPublicKeyPEM(pub),
		})
	}
	return nil, ErrNoIssuerFound
}

func (v *Issuer) setPrivateKey(k *ecdsa.PrivateKey) error {
	v.privateKey = k
	v.publicKey = &k.PublicKey
	kid, err := computeKeyID(&k.PublicKey)
	if err != nil {
		return fmt.Errorf("issuer: compute key id: %w", err)
	}
	v.kid = kid
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: k},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"kid": kid,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("issuer: create signer: %w", err)
	}
	v.signer = signer
	return nil
}

func (v *Issuer) setPublicKey(k *ecdsa.PublicKey) error {
	v.publicKey = k
	kid, err := computeKeyID(k)
	if err != nil {
		return fmt.Errorf("issuer: compute key id: %w", err)
	}
	v.kid = kid
	return nil
}

// TokenOption customizes a token minted by Issuer.SignToken.
type TokenOption func(*tokenOptions)

type tokenOptions struct {
	nonce    string
	provider string
	roles    []string
	custom   map[string]any
}

// WithNonce sets the nonce claim, binding the token to the OAuth2 request it
// originated from. A random nonce is used when unset.
func WithNonce(nonce string) TokenOption {
	return func(o *tokenOptions) { o.nonce = nonce }
}

// WithProvider records which sign-in provider established the identity (e.g.
// "google", "microsoft", "basic-auth").
func WithProvider(provider string) TokenOption {
	return func(o *tokenOptions) { o.provider = provider }
}

// WithRoles overrides the roles resolved from the issuer's RoleStore. Omit for
// automatic resolution at mint time.
func WithRoles(roles []string) TokenOption {
	return func(o *tokenOptions) { o.roles = roles }
}

// WithClaim adds an arbitrary custom claim to the token.
func WithClaim(key string, value any) TokenOption {
	return func(o *tokenOptions) {
		if o.custom == nil {
			o.custom = make(map[string]any)
		}
		o.custom[key] = value
	}
}

// SignToken issues a new guard session token for the given email, valid for
// ttl. The token carries the identity claims plus any roles resolved from the
// configured RoleStore (or the WithRoles override). Requires a private key
// (issuer mode); validation-only issuers return an error.
func (v *Issuer) SignToken(email string, ttl time.Duration, opts ...TokenOption) (string, error) {
	if v.signer == nil {
		return "", ErrNoPrivateKey
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	o := tokenOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.nonce == "" {
		nonce, err := newNonce()
		if err != nil {
			return "", err
		}
		o.nonce = nonce
	}
	roles := o.roles
	if roles == nil && v.roleStore != nil {
		resolved, err := v.roleStore.RolesByEmail(context.Background(), email)
		if err != nil {
			return "", fmt.Errorf("issuer: resolve roles for %q: %w", email, err)
		}
		roles = resolved
	}

	now := time.Now()
	claims := issuerClaims{
		Claims: jwt.Claims{
			Issuer:   v.issuer,
			Subject:  email,
			Expiry:   jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt: jwt.NewNumericDate(now),
		},
		Email:         email,
		EmailVerified: true,
		Nonce:         o.nonce,
		Provider:      o.provider,
		Roles:         roles,
		custom:        o.custom,
	}
	return jwt.Signed(v.signer).Claims(claims).Serialize()
}

// ValidateToken verifies the token signature, issuer, expiry, and that an
// email claim is present. Returns the user on success.
func (v *Issuer) ValidateToken(_ context.Context, token string) (*User, error) {
	if v.publicKey == nil {
		return nil, ErrNoPublicKey
	}
	tk, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	if len(tk.Headers) > 0 && tk.Headers[0].KeyID != "" && tk.Headers[0].KeyID != v.kid {
		return nil, errors.New("token signed with an unknown key")
	}
	var claims issuerClaims
	if err := tk.Claims(v.publicKey, &claims); err != nil {
		return nil, err
	}

	expected := jwt.Expected{}
	if v.issuer != "" {
		expected.Issuer = v.issuer
	}
	if err := claims.ValidateWithLeeway(expected, time.Minute); err != nil {
		return nil, err
	}
	if claims.Email == "" {
		return nil, errors.New("missing email")
	}
	if !claims.EmailVerified {
		return nil, errors.New("email is not verified")
	}

	raw, err := extractRawClaims(token)
	if err != nil {
		return nil, err
	}
	return &User{
		Id:            claims.Email,
		Email:         claims.Email,
		VerifiedEmail: true,
		Sub:           claims.Subject,
		Roles:         claims.Roles,
		Provider:      claims.Provider,
		Claims:        raw,
	}, nil
}

// JWKS returns the public key in JWK Set form, suitable for
// /.well-known/jwks.json. Returns an error when no public key is available.
func (v *Issuer) JWKS() (jose.JSONWebKeySet, error) {
	if v.publicKey == nil {
		return jose.JSONWebKeySet{}, ErrNoPublicKey
	}
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       v.publicKey,
			KeyID:     v.kid,
			Algorithm: string(jose.ES256),
			Use:       "sig",
		}},
	}, nil
}

// PublicKeyPEM returns the PEM-encoded public key for manual distribution.
func (v *Issuer) PublicKeyPEM() ([]byte, error) {
	if v.publicKey == nil {
		return nil, ErrNoPublicKey
	}
	return ecPublicKeyPEM(v.publicKey), nil
}

// KeyID returns the RFC 7638 thumbprint identifying the signing key.
func (v *Issuer) KeyID() string { return v.kid }

// IssuerURL returns the configured issuer, if any.
func (v *Issuer) IssuerURL() string { return v.issuer }

// issuerClaims holds the claims written into guard session tokens.
type issuerClaims struct {
	jwt.Claims
	Email         string         `json:"email"`
	EmailVerified bool           `json:"email_verified"`
	Nonce         string         `json:"nonce,omitempty"`
	Provider      string         `json:"provider,omitempty"`
	Roles         []string       `json:"roles,omitempty"`
	custom        map[string]any `json:"-"`
}

// MarshalJSON merges the standard claims with any custom claims added via
// WithClaim, so they appear as top-level JWT claims.
func (c issuerClaims) MarshalJSON() ([]byte, error) {
	type alias issuerClaims
	base, err := json.Marshal(alias(c))
	if err != nil {
		return nil, err
	}
	if len(c.custom) == 0 {
		return base, nil
	}
	var m map[string]any
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	for k, v := range c.custom {
		m[k] = v
	}
	return json.Marshal(m)
}

// extractRawClaims decodes the token payload into a plain map so consumers
// that need more than the normalized User fields can inspect the full claim
// set, including custom claims added with WithClaim.
func extractRawClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func newNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func computeKeyID(pub *ecdsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

func parseECPrivateKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an EC private key")
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
}

func parseECPublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an EC public key")
	}
	return pub, nil
}

func ecPublicKeyPEM(pub *ecdsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err) // marshaling an EC public key cannot fail
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func mustECPublicKeyPEM(pub *ecdsa.PublicKey) []byte {
	return ecPublicKeyPEM(pub)
}

func fetchJWKS(ctx context.Context, url string) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	var keyset jose.JSONWebKeySet
	if err := json.Unmarshal(body, &keyset); err != nil {
		return jose.JSONWebKeySet{}, err
	}
	return keyset, nil
}
