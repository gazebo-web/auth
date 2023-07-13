package authentication

import (
	"context"
	"errors"
	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
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
func (auth *firebaseAuthentication) VerifyJWT(ctx context.Context, token string) (jwt.Claims, error) {
	if err := validateJWT(token); err != nil {
		return nil, err
	}

	verifiedToken, err := auth.firebaseAuth.VerifyIDToken(ctx, token)
	if err != nil {
		return nil, err
	}

	return NewFirebaseClaims(*verifiedToken), nil
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
//	if claims, err := auth.VerifyJWT(ctx, token); err != nil {
//		log.Fatalf("failed to verify jwt: %v\n", err)
//	}
//
//	sub, err := claims.GetSubject()
//	if err != nil {
//		log.Fatalf("missing subject: %v\n", err)
//	}
//
//	log.Println("Subject:", sub)
func NewFirebaseWithTokenVerifier(firebaseAuth FirebaseTokenVerifier) Authentication {
	return &firebaseAuthentication{
		firebaseAuth: firebaseAuth,
	}
}

// firebaseAuth uses the firebase application to refresh the keys used to verify the token signature.
// The firebase.App has an internal mechanism to avoid repeating this operation for every request.
type firebaseAuth struct {
	client *auth.Client
}

// VerifyIDToken gets a new public key in case a key rotation has been requested, and verifies the given token.
func (auth *firebaseAuth) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	return auth.client.VerifyIDToken(ctx, idToken)
}

// NewFirebase initializes a new FirebaseTokenVerifier implementation using a Firebase application, and it's in
// charge of refreshing the public key used to verify tokens every time a new key rotation happens.
//
//	fbAuth, err := NewFirebase(app)
//	if err != nil {
//		log.Fatalf("failed to initialize firebase authentication: %v\n", err)
//	}
//	auth := NewFirebaseWithTokenVerifier(fbAuth)
//
// See the NewFirebaseWithTokenVerifier documentation for more information on how to use the token verifier.
func NewFirebase(app *firebase.App) (FirebaseTokenVerifier, error) {
	client, err := app.Auth(context.Background())
	if err != nil {
		return nil, err
	}
	return &firebaseAuth{
		client: client,
	}, nil
}

var _ jwt.Claims = (*firebaseClaims)(nil)
var _ EmailClaimer = (*firebaseClaims)(nil)

// firebaseClaims implements the jwt.Claims interface on auth.Token.
type firebaseClaims auth.Token

// GetEmail gets the firebase user's email address.
func (ft firebaseClaims) GetEmail() (string, error) {
	const key = "email"
	v, err := ft.getCustomClaim(key)
	if err != nil {
		return "", err
	}
	email, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("invalid %s value: should be a string", key)
	}
	return email, nil
}

// getCustomClaim gets the value from the given key.
func (ft firebaseClaims) getCustomClaim(key string) (any, error) {
	v, ok := ft.Claims[key]
	if !ok {
		return nil, fmt.Errorf("failed to get %s value: not found", key)
	}
	return v, nil
}

// GetExpirationTime gets the expiration time (exp) from the JWT.
func (ft firebaseClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(ft.Expires, 0)), nil
}

// GetIssuedAt gets the issues at value (iat) from the JWT.
func (ft firebaseClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(time.Unix(ft.IssuedAt, 0)), nil
}

// GetNotBefore gets the not-before time (nbf) from the JWT.
// This method is not implemented given that Firebase doesn't provide support for this value.
func (ft firebaseClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, errors.New("not implemented")
}

// GetIssuer gets the issuer (iss) from the JWT.
func (ft firebaseClaims) GetIssuer() (string, error) {
	return ft.Issuer, nil
}

// GetSubject gets the subject (sub) from the JWT.
func (ft firebaseClaims) GetSubject() (string, error) {
	return ft.Subject, nil
}

// GetAudience gets the audiences (aud) from the JWT.
func (ft firebaseClaims) GetAudience() (jwt.ClaimStrings, error) {
	return []string{ft.Audience}, nil
}

// NewFirebaseClaims initializes a new set of claims from the given firebase token.
func NewFirebaseClaims(token auth.Token) jwt.Claims {
	return firebaseClaims(token)
}

// NewFirebaseTestToken creates a new auth.Token for testing purposes.
func NewFirebaseTestToken() auth.Token {
	return auth.Token{
		AuthTime: 3600,
		Issuer:   "firebase",
		Audience: "gazebosim.org",
		Expires:  time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt: time.Now().Unix(),
		Subject:  "gazebo-web",
		UID:      "1234",
		Firebase: auth.FirebaseInfo{
			SignInProvider: "google",
		},
		Claims: map[string]interface{}{
			"email": "test@gazebosim.org",
		},
	}
}
