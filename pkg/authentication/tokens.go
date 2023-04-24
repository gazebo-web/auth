package authentication

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

// tokens is an Authentication implementation using JSON Web Tokens as an authentication system.
type tokens struct {
	publicKey []byte
}

// VerifyCredentials verifies that the given credentials are valid for the current provider.
func (auth *tokens) VerifyCredentials(ctx context.Context, credentials Credentials) error {
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

// validateScheme validates that the given credentials contains a valid scheme.
// This method allows to enforce developers to pass the correct type of credentials.
func (auth *tokens) validateScheme(credentials Credentials) error {
	if len(credentials.Scheme) == 0 {
		return errors.New("no scheme provided")
	}
	if credentials.Scheme != SchemeBearer {
		return errors.New("invalid scheme, should be a bearer token")
	}
	return nil
}

// validateProvider validates that the given credentials contains a valid Auth0 token.
func (auth *tokens) validateToken(credentials Credentials) error {
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

func (auth *tokens) keyFunc(token *jwt.Token) (interface{}, error) {
	return jwt.ParseRSAPublicKeyFromPEM(auth.publicKey)
}

// NewTokenAuthentication initializes a new Authentication implementation using tokens and JWT as an
// authentication system. It receives the public key used to verify the signature of JWTs.
func NewTokenAuthentication(key []byte) Authentication {
	return &tokens{
		publicKey: key,
	}
}
