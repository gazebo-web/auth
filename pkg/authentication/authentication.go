package authentication

import (
	"context"
)

// TokenAuthentication is the signature that a function should fulfill in order to verify an access token.
type TokenAuthentication func(context.Context, string) error

// Authentication contains a set of methods to authenticate users through different authentication providers such as
// Auth0, Google Identity Platform, and such.
type Authentication interface {
	// VerifyJWT verifies that the given token is a valid JWT and was correctly signed by the Authentication provider.
	VerifyJWT(ctx context.Context, token string) error
}
