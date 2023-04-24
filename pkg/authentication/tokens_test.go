package authentication

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/suite"
	"os"
	"testing"
	"time"
)

type tokenTestSuite struct {
	suite.Suite
	authentication Authentication
	token          *jwt.Token
	publicKey      []byte
	privateKey     *rsa.PrivateKey
}

func TestTokenTestSuite(t *testing.T) {
	suite.Run(t, new(tokenTestSuite))
}

func (suite *tokenTestSuite) SetupSuite() {
	var err error
	suite.Require().NoError(err)
	suite.token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(map[string]interface{}{
		"exp": time.Hour,
		"iat": time.Now(),
	}))

	pk, err := os.ReadFile("./testdata/key.private.pem")
	suite.Require().NoError(err)

	// Use the PEM decoder and parse the private key
	block, _ := pem.Decode(pk)
	suite.privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)

	suite.publicKey, err = os.ReadFile("./testdata/key.pem")

	suite.authentication = NewTokenAuthentication(suite.publicKey)
}

func (suite *tokenTestSuite) SetupTest() {

}

func (suite *tokenTestSuite) TestVerifyCredentials_InvalidScheme() {
	ctx := context.Background()
	creds := Credentials{
		Scheme: "",
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))

	creds = Credentials{
		Scheme: "BasicAuth",
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))
}

func (suite *tokenTestSuite) TestVerifyCredentials_InvalidToken() {
	ctx := context.Background()
	creds := Credentials{
		Scheme: SchemeBearer,
		Token:  "",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))

	creds = Credentials{
		Scheme: SchemeBearer,
		Token:  "1234",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))

	creds = Credentials{
		Scheme: SchemeBearer,
		Token:  ".eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))

	creds = Credentials{
		Scheme: SchemeBearer,
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))

	creds = Credentials{
		Scheme: SchemeBearer,
		Token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.",
	}
	suite.Assert().Error(suite.authentication.VerifyCredentials(ctx, creds))
}

func (suite *tokenTestSuite) TestVerifyCredentials_Success() {
	ctx := context.Background()

	signedToken, err := suite.token.SignedString(suite.privateKey)
	suite.Require().NoError(err)

	creds := Credentials{
		Scheme: SchemeBearer,
		Token:  signedToken,
	}
	suite.Assert().NoError(suite.authentication.VerifyCredentials(ctx, creds))
}

func (suite *tokenTestSuite) TearDownTest() {

}

func (suite *tokenTestSuite) TearDownSuite() {

}
