package authentication

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

// bearerToken is an Authentication implementation using Bearer tokens and JWT as an authentication system.
type bearerToken struct {
	publicKey []byte
}

// VerifyCredentials verifies that the given credentials are valid for the current provider.
func (auth *bearerToken) VerifyCredentials(ctx context.Context, credentials Credentials) error {
	if err := auth.validateScheme(credentials); err != nil {
		return err
	}
	if err := auth.validateToken(credentials); err != nil {
		return err
	}
	token, err := jwt.Parse(credentials.Token, auth.keyFunc)
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("token is not valid")
	}
	return nil
}

// validateScheme validates that the given credentials contains a valid Auth0 scheme.
func (auth *bearerToken) validateScheme(credentials Credentials) error {
	if len(credentials.Scheme) == 0 {
		return errors.New("no scheme provided")
	}
	if credentials.Scheme != SchemeBearer {
		return errors.New("invalid scheme, should be a bearer token")
	}
	return nil
}

// validateProvider validates that the given credentials contains a valid Auth0 token.
func (auth *bearerToken) validateToken(credentials Credentials) error {
	if len(credentials.Token) == 0 {
		return errors.New("no token provided")
	}
	parts := strings.Split(credentials.Token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token")
	}
	header := parts[0]
	payload := parts[1]
	sig := parts[2]
	if len(header) == 0 {
		return errors.New("token contains no header")
	}
	if len(payload) == 0 {
		return errors.New("token contains no payload")
	}
	if len(sig) == 0 {
		return errors.New("token contains no signature")
	}
	return nil
}

func (auth *bearerToken) keyFunc(token *jwt.Token) (interface{}, error) {
	return jwt.ParseRSAPublicKeyFromPEM(auth.publicKey)
}

// NewAuth0 initializes a new Authentication implementation using Auth0 as an authentication provider.
func NewAuth0(key []byte) Authentication {
	return &bearerToken{
		publicKey: key,
	}
}
