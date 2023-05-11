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

// firebaseAuthentication is an Authentication implementation using Firebase.
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

// firebaseAuth wraps a standard Firebase application object to implement internal interfaces.
type firebaseAuth struct {
	client *auth.Client
	app    *firebase.App
}

// VerifyIDToken gets a new public key in case a key rotation has been requested, and verifies the given token.
func (auth *firebaseAuth) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	client, err := auth.Client()
	if err != nil {
		return nil, err
	}
	return client.VerifyIDToken(ctx, idToken)
}

// Client returns the underlying authentication client used to perform auth operations on Firebase.
func (auth *firebaseAuth) Client() (*auth.Client, error) {
	var err error
	if auth.client == nil {
		auth.client, err = auth.app.Auth(context.Background())
	}
	return auth.client, err
}

// NewFirebase initializes a new FirebaseTokenVerifier implementation using a Firebase application, and it's in
// charge of refreshing the public key used to verify tokens every time a new key rotation happens.
//
//	auth := NewFirebaseWithTokenVerifier(NewFirebase(app))
//	if err := auth.VerifyJWT(ctx, token); err != nil {
//		log.Fatalf("failed to verify jwt: %v\n", err)
//	}
func NewFirebase(app *firebase.App) FirebaseTokenVerifier {
	return &firebaseAuth{
		app: app,
	}
}
