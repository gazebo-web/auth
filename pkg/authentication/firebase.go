package authentication

import (
	"context"
	"firebase.google.com/go/v4/auth"
)

// FirebaseTokenVerifier contains a method that allows verifying a Token signed by Firebase.
type FirebaseTokenVerifier interface {
	VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error)
}

// firebaseAuthentication is a Authentication implementation using Firebase.
type firebaseAuthentication struct {
	firebaseAuth FirebaseTokenVerifier
}

// VerifyJWT verifies that the given Token is a valid JWT and was correctly signed by Firebase.
func (auth *firebaseAuthentication) VerifyJWT(ctx context.Context, token string) error {
	if err := validateJWT(token); err != nil {
		return err
	}
	_, err := auth.firebaseAuth.VerifyIDToken(ctx, token)
	if err != nil {
		return err
	}
	return nil
}

// NewFirebaseWithTokenVerifier initializes a new Authentication implementation using Firebase.
// You can read more about Verifying ID tokens with Firebase: https://firebase.google.com/docs/auth/admin/verify-id-tokens
//
//		client, err := app.Auth(ctx)
//		if err != nil {
//	       log.Fatalf("error getting Auth client: %v\n", err)
//		}
//		auth := NewFirebaseWithTokenVerifier(client)
//		err := auth.VerifyJWT(ctx, token)
//		if err != nil {
//	       log.Fatalf("failed to verify jwt: %v\n", err)
//		}
func NewFirebaseWithTokenVerifier(firebaseAuth FirebaseTokenVerifier) Authentication {
	return &firebaseAuthentication{
		firebaseAuth: firebaseAuth,
	}
}
