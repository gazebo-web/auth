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
	suite.token = auth.Token{
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
	ctx := context.Background()

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, ""))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, "1234"))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, ".eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY"))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY"))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ."))
}

func (suite *firebaseTestSuite) TestVerifyCredentials_FirebaseReturnsError() {
	ctx := context.Background()

	err := errors.New("firebase failed to verify Token")

	suite.authentication = NewFirebaseWithTokenVerifier(verifierWithError(err))

	suite.Assert().ErrorIs(suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaXJlYmFzZSIsImF1ZCI6ImdhemVib3NpbS5vcmciLCJzdWIiOiJnYXplYm8td2ViIiwidWlkIjoiMTIzNCIsImlhdCI6MTUxNjIzOTAyMn0.JTr0bynKo2txHf5uE7qinJ063Nrbjb8o_bmv_EttP-eMpN-ommwVu5zqO4WC3jn5jOThQge0i17CZhWaoalcJQ"), err)
}

func (suite *firebaseTestSuite) TestVerifyCredentials_Success() {
	ctx := context.Background()

	suite.authentication = NewFirebaseWithTokenVerifier(verifierWithToken(&suite.token))

	suite.Assert().NoError(suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmaXJlYmFzZSIsImF1ZCI6ImdhemVib3NpbS5vcmciLCJzdWIiOiJnYXplYm8td2ViIiwidWlkIjoiMTIzNCIsImlhdCI6MTUxNjIzOTAyMn0.JTr0bynKo2txHf5uE7qinJ063Nrbjb8o_bmv_EttP-eMpN-ommwVu5zqO4WC3jn5jOThQge0i17CZhWaoalcJQ"))
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
	token := NewFirebaseTestToken()

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

func TestNewFirebaseClaims_GetEmail(t *testing.T) {
	assert.Implements(t, (*EmailClaimer)(nil), new(firebaseClaims))

	token := NewFirebaseTestToken()
	claims := NewFirebaseClaims(token)

	email, ok := claims.(EmailClaimer)
	assert.True(t, ok)

	value, err := email.GetEmail()
	assert.NoError(t, err)
	assert.Equal(t, token.Claims["email"], value)
}

func TestNewFirebaseClaims_GetEmail_MissingValue(t *testing.T) {
	assert.Implements(t, (*EmailClaimer)(nil), new(firebaseClaims))

	token := NewFirebaseTestToken()
	token.Claims = map[string]interface{}{}
	claims := NewFirebaseClaims(token)

	email, ok := claims.(EmailClaimer)
	assert.True(t, ok)

	_, err := email.GetEmail()
	assert.Error(t, err)
}

func TestNewFirebaseClaims_GetEmail_InvalidValue(t *testing.T) {
	token := NewFirebaseTestToken()
	token.Claims = map[string]interface{}{
		"email": 1234,
	}
	claims := NewFirebaseClaims(token)

	email, ok := claims.(EmailClaimer)
	assert.True(t, ok)

	_, err := email.GetEmail()
	assert.Error(t, err)
}
