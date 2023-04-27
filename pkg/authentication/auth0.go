package authentication

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

var (
	// ErrTokenNoProvided is returned when no token is provided.
	ErrTokenNoProvided = errors.New("no token provided")
	// ErrTokenInvalid is returned when a certain token is invalid.
	ErrTokenInvalid = errors.New("token is not valid")
	// ErrTokenMalformed is returned when the token doesn't match the expected token form.
	// 	Example: JWT should have 3 parts, header, payload and signature.
	ErrTokenMalformed = errors.New("token is malformed")

	// ErrJWTNoHeader is returned when a certain JWT contains no header.
	ErrJWTNoHeader = errors.New("jwt contains no header")

	// ErrJWTNoPayload is returned when a certain JWT contains no payload.
	ErrJWTNoPayload = errors.New("jwt contains no payload")

	// ErrJWTNoSignature is returned when a certain JWt contains no signature.
	ErrJWTNoSignature = errors.New("jwt contains no signature")
)

// auth0 is an Authentication implementation using Auth0 as an authentication provider.
type auth0 struct {
	publicKey []byte
}

// VerifyJWT verifies that the given token is a valid JWT and was correctly signed by Auth0.
func (auth *auth0) VerifyJWT(ctx context.Context, token string) error {
	if err := auth.validateJWT(token); err != nil {
		return err
	}
	parsedToken, err := jwt.Parse(token, auth.keyFunc)
	if err != nil {
		return err
	}
	if !parsedToken.Valid {
		return ErrTokenInvalid
	}
	return nil
}

// validateJWT validates that the given token is a valid JWT.
func (auth *auth0) validateJWT(token string) error {
	if len(token) == 0 {
		return ErrTokenNoProvided
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ErrTokenMalformed
	}
	header := parts[0]
	payload := parts[1]
	sig := parts[2]
	if len(header) == 0 {
		return ErrJWTNoHeader
	}
	if len(payload) == 0 {
		return ErrJWTNoPayload
	}
	if len(sig) == 0 {
		return ErrJWTNoSignature
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
