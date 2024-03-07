package authentication

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/suite"
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
		"sub": "gazebo-web",
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
	AssertJsonWebTokenValidation(suite.T(), suite.authentication)
}

func (suite *auth0TestSuite) TestVerifyCredentials_Success() {
	ctx := context.Background()

	signedToken, err := suite.token.SignedString(suite.privateKey)
	suite.Require().NoError(err)

	claims, err := suite.authentication.VerifyJWT(ctx, signedToken)
	suite.Assert().NoError(err)

	sub, err := claims.GetSubject()
	suite.Assert().NoError(err)
	suite.Assert().NotEmpty(sub)
	suite.Assert().Equal("gazebo-web", sub)
}

func (suite *auth0TestSuite) TearDownTest() {

}

func (suite *auth0TestSuite) TearDownSuite() {

}
