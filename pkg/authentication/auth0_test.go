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

type auth0TestSuite struct {
	suite.Suite
	authentication Authentication
	token          *jwt.Token
	publicKey      []byte
	privateKey     *rsa.PrivateKey
}

func TestAuth0TestSuite(t *testing.T) {
	suite.Run(t, new(auth0TestSuite))
}

func (suite *auth0TestSuite) SetupSuite() {
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
	suite.Require().NoError(err)

	suite.publicKey, err = os.ReadFile("./testdata/key.pem")
	suite.Require().NoError(err)

	suite.authentication = NewAuth0(suite.publicKey)
}

func (suite *auth0TestSuite) SetupTest() {

}

func (suite *auth0TestSuite) TestVerifyCredentials_InvalidToken() {
	ctx := context.Background()

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, ""))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, "1234"))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, ".eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY"))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY"))

	suite.Assert().Error(suite.authentication.VerifyJWT(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ."))
}

func (suite *auth0TestSuite) TestVerifyCredentials_Success() {
	ctx := context.Background()

	signedToken, err := suite.token.SignedString(suite.privateKey)
	suite.Require().NoError(err)

	suite.Assert().NoError(suite.authentication.VerifyJWT(ctx, signedToken))
}

func (suite *auth0TestSuite) TearDownTest() {

}

func (suite *auth0TestSuite) TearDownSuite() {

}
