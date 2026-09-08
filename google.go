package bearer

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/api/idtoken"
)

var _ TokenValidator = (*GoogleTokenValidator)(nil)

type GoogleTokenValidator struct {
	ClientId  string
	Validator *idtoken.Validator
}

func NewGoogleTokenValidator(clientId string) *GoogleTokenValidator {
	validator, err := idtoken.NewValidator(context.Background())
	if err != nil {
		panic(fmt.Sprintf("failed to create token validator: %v", err))
	}
	return &GoogleTokenValidator{ClientId: clientId, Validator: validator}
}

func (g *GoogleTokenValidator) ValidateToken(ctx context.Context, token string) (*User, error) {
	payload, err := g.Validator.Validate(ctx, token, g.ClientId)
	if err != nil {
		return nil, err
	}
	email, okEmail := payload.Claims["email"].(string)
	if !okEmail || email == "" {
		return nil, errors.New("missing email")
	}
	verified, okVerified := payload.Claims["email_verified"].(bool)
	if !verified || !okVerified {
		return nil, errors.New("email is not verified")
	}
	sub, _ := payload.Claims["sub"].(string)

	return &User{Id: sub, Email: email, VerifiedEmail: verified, Sub: sub}, nil
}
