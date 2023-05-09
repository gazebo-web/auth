package authentication

import (
	"context"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
)

// FirebaseTokenVerifier verifies a Token signed by Firebase. It was created to allow developers to mock VerifyIDToken
// calls when testing.
type FirebaseTokenVerifier interface {
	// VerifyIDToken verifies a Token signed by Firebase. The idToken is the bearer token from an HTTP request:
	//	HTTP headers:
	//	- Authorization: Bearer <idToken>
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
//	client, err := app.Auth(ctx)
//	if err != nil {
//		log.Fatalf("error getting Auth client: %v\n", err)
//	}
//
//	auth := NewFirebaseWithTokenVerifier(client)
//	if err := auth.VerifyJWT(ctx, token); err != nil {
//		log.Fatalf("failed to verify jwt: %v\n", err)
//	}
func NewFirebaseWithTokenVerifier(firebaseAuth FirebaseTokenVerifier) Authentication {
	return &firebaseAuthentication{
		firebaseAuth: firebaseAuth,
	}
}

// firebaseRefresher uses the firebase application to refresh the keys used to verify the token signature.
// The firebase.App has an internal mechanism to avoid repeating this operation for every request.
type firebaseRefresher struct {
	app *firebase.App
}

// VerifyIDToken gets a new public key in case a key rotation has been requested, and verifies the given token.
func (auth *firebaseRefresher) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	client, err := auth.app.Auth(ctx)
	if err != nil {
		return nil, err
	}
	return client.VerifyIDToken(ctx, idToken)
}

// NewFirebaseRefresher initializes a new FirebaseTokenVerifier implementation using a Firebase application, and it's in
// charge of refreshing the public key used to verify tokens every time a new key rotation happens.
//
//	auth := NewFirebaseWithTokenVerifier(NewFirebaseRefresher(app))
//	if err := auth.VerifyJWT(ctx, token); err != nil {
//		log.Fatalf("failed to verify jwt: %v\n", err)
//	}
func NewFirebaseRefresher(app *firebase.App) FirebaseTokenVerifier {
	return &firebaseRefresher{
		app: app,
	}
}
