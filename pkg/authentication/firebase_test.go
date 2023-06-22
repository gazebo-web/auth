package authentication

import (
	"context"
	"errors"
	"firebase.google.com/go/v4/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

type firebaseTestSuite struct {
	suite.Suite
	authentication Authentication
	token          auth.Token
}

func TestFirebaseTestSuite(t *testing.T) {
	suite.Run(t, new(firebaseTestSuite))
}

func (suite *firebaseTestSuite) SetupSuite() {
	suite.token = NewFirebaseToken()
}

func NewFirebaseToken() auth.Token {
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
	}
}

func (suite *firebaseTestSuite) TestVerifyCredentials_InvalidToken() {
	AssertTokenValidation(suite.T(), suite.authentication)
}

func (suite *firebaseTestSuite) TestVerifyCredentials_FirebaseReturnsError() {
	ctx := context.Background()

	expectedError := errors.New("firebase failed to verify Token")

	suite.authentication = NewFirebaseWithTokenVerifier(verifierWithError(expectedError))

	_, err := suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaXJlYmFzZSIsImF1ZCI6ImdhemVib3NpbS5vcmciLCJzdWIiOiJnYXplYm8td2ViIiwidWlkIjoiMTIzNCIsImlhdCI6MTUxNjIzOTAyMn0.JTr0bynKo2txHf5uE7qinJ063Nrbjb8o_bmv_EttP-eMpN-ommwVu5zqO4WC3jn5jOThQge0i17CZhWaoalcJQ")
	suite.Assert().ErrorIs(err, expectedError)
}

func (suite *firebaseTestSuite) TestVerifyCredentials_Success() {
	ctx := context.Background()

	suite.authentication = NewFirebaseWithTokenVerifier(verifierWithToken(&suite.token))

	claims, err := suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaXJlYmFzZSIsImF1ZCI6ImdhemVib3NpbS5vcmciLCJzdWIiOiJnYXplYm8td2ViIiwidWlkIjoiMTIzNCIsImlhdCI6MTUxNjIzOTAyMn0.JTr0bynKo2txHf5uE7qinJ063Nrbjb8o_bmv_EttP-eMpN-ommwVu5zqO4WC3jn5jOThQge0i17CZhWaoalcJQ")
	suite.Assert().NoError(err)

	sub, err := claims.GetSubject()
	suite.Assert().NoError(err)
	suite.Assert().NotEmpty(sub)
	suite.Assert().Equal("gazebo-web", sub)
}

type testVerifier struct {
	Token *auth.Token
	Error error
}

func (v testVerifier) VerifyIDToken(ctx context.Context, idToken string) (*auth.Token, error) {
	if v.Token != nil {
		return v.Token, nil
	} else if v.Error != nil {
		return nil, v.Error
	} else {
		return nil, errors.New("failed to verify Token")
	}
}

func verifierWithToken(token *auth.Token) FirebaseTokenVerifier {
	return testVerifier{Token: token}
}

func verifierWithError(err error) FirebaseTokenVerifier {
	return testVerifier{Error: err}
}

func TestNewFirebaseClaims(t *testing.T) {
	token := NewFirebaseToken()

	claims := NewFirebaseClaims(token)
	assert.NotNil(t, claims)

	date, err := claims.GetExpirationTime()
	assert.NoError(t, err)
	assert.NotNil(t, date)
	assert.True(t, time.Unix(token.Expires, 0).Equal(date.Time))

	date, err = claims.GetIssuedAt()
	assert.NoError(t, err)
	assert.NotNil(t, date)
	assert.True(t, time.Unix(token.IssuedAt, 0).Equal(date.Time))

	_, err = claims.GetNotBefore()
	assert.Error(t, err)
	assert.ErrorContains(t, err, "not implemented")

	iss, err := claims.GetIssuer()
	assert.NoError(t, err)
	assert.NotEmpty(t, iss)
	assert.Equal(t, token.Issuer, iss)

	sub, err := claims.GetSubject()
	assert.NoError(t, err)
	assert.NotEmpty(t, sub)
	assert.Equal(t, token.Subject, sub)

	aud, err := claims.GetAudience()
	assert.NoError(t, err)
	assert.NotEmpty(t, aud)
	assert.EqualValues(t, []string{token.Audience}, aud)
}
