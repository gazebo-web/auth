package authentication

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenAuthentication defines the function signature for access token
// validators.
// These functions are used by BearerAccessTokenAuthFuncGRPC to validate
// incoming access tokens are valid.
type AccessTokenAuthentication func(context.Context, string) error

// JsonWebTokenAuthentication is the signature that a function should fulfill
// in order to verify a JWT token.
type JsonWebTokenAuthentication func(context.Context, string) (jwt.Claims, error)

// Authentication contains a set of methods to authenticate users through
// different authentication providers such as Auth0, Google Identity Platform,
// and such.
type Authentication interface {
	// VerifyJWT verifies that the given token is a valid JWT and was correctly
	// signed by the Authentication provider.
	VerifyJWT(ctx context.Context, token string) (jwt.Claims, error)
}

// EmailClaimer allows to get an email from a custom JWT claim.
// NOTE: Not all authentication providers embed an email in their JWT.
type EmailClaimer interface {
	// GetEmail returns the user's email from a custom JWT claim.
	GetEmail() (string, error)
}

// CustomClaimer allows getting custom claims from JWTs.
type CustomClaimer interface {
	// GetCustomClaim returns the value of the claim identified by the given key.
	// If key does not exist, it returns an error instead.
	GetCustomClaim(key string) (any, error)
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
