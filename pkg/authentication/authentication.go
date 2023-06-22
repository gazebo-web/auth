package authentication

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
)

// TokenAuthentication is the signature that a function should fulfill in order to verify an access token.
type TokenAuthentication func(context.Context, string) error

// Authentication contains a set of methods to authenticate users through different authentication providers such as
// Auth0, Google Identity Platform, and such.
type Authentication interface {
	// VerifyJWT verifies that the given token is a valid JWT and was correctly signed by the Authentication provider.
	VerifyJWT(ctx context.Context, token string) (jwt.Claims, error)
}

// validateJWT validates that the given token is a valid JWT.
func validateJWT(token string) error {
	if len(token) == 0 {
		return ErrTokenNotProvided
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: malformed", ErrTokenInvalid)
	}
	header := parts[0]
	payload := parts[1]
	sig := parts[2]
	if len(header) == 0 {
		return fmt.Errorf("%w: no jwt header", ErrTokenInvalid)
	}
	if len(payload) == 0 {
		return fmt.Errorf("%w: no jwt payload", ErrTokenInvalid)
	}
	if len(sig) == 0 {
		return fmt.Errorf("%w: no jwt signature", ErrTokenInvalid)
	}
	return nil
}
