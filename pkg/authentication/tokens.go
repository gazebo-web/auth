package authentication

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

// auth0 is an Authentication implementation using Auth0 as an authentication provider.
type auth0 struct {
	publicKey []byte
}

// VerifyJWT verifies that the given token is a valid JWT and was correctly signed by Auth0.
func (auth *auth0) VerifyJWT(ctx context.Context, token string) error {
	if err := auth.validateToken(token); err != nil {
		return err
	}
	parsedToken, err := jwt.Parse(token, auth.keyFunc)
	if err != nil {
		return err
	}
	if !parsedToken.Valid {
		return errors.New("token is not valid")
	}
	return nil
}

// validateToken validates that the given token is a valid JWT.
func (auth *auth0) validateToken(token string) error {
	if len(token) == 0 {
		return errors.New("no token provided")
	}
	parts := strings.Split(token, ".")
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

func (auth *auth0) keyFunc(token *jwt.Token) (interface{}, error) {
	return jwt.ParseRSAPublicKeyFromPEM(auth.publicKey)
}

// NewAuth0 initializes a new Authentication implementation using auth0 and JWT as an
// authentication system. It receives the public key used to verify the signature of JWTs.
func NewAuth0(key []byte) Authentication {
	return &auth0{
		publicKey: key,
	}
}
