package authentication

import (
	"context"
)

const (
	// SchemeBearer defines a Bearer token scheme.
	SchemeBearer = "Bearer"
)

// Credentials contains information about an authentication request.
type Credentials struct {
	// Scheme contains information about the type of credentials being used.
	Scheme string
	// Token contains information the actual credential.
	Token string
}

// Authentication contains a set of methods to authenticate users through different authentication providers such as
// Auth0, PlatformIdentity, and such.
type Authentication interface {
	// VerifyCredentials verifies that the given credentials are valid and can be granted access.
	VerifyCredentials(ctx context.Context, credentials Credentials) error
}
