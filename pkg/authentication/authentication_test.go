package authentication

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func AssertTokenValidation(t *testing.T, authentication Authentication) {
	ctx := context.TODO()
	_, err := authentication.VerifyJWT(ctx, "")
	assert.Error(t, err)

	_, err = authentication.VerifyJWT(ctx, "1234")
	assert.Error(t, err)

	_, err = authentication.VerifyJWT(ctx, ".eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY")
	assert.Error(t, err)

	_, err = authentication.VerifyJWT(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..9QkZxtBr6Z5uuZEYNFfjRNBlGhY5hGzBUG71DgF-IJY")
	assert.Error(t, err)

	_, err = authentication.VerifyJWT(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL215LWRvbWFpbi5hdXRoMC5jb20vIiwic3ViIjoiYXV0aDB8MTIzNDU2IiwiYXVkIjpbImh0dHBzOi8vZXhhbXBsZS5jb20vaGVhbHRoLWFwaSIsImh0dHBzOi8vbXktZG9tYWluLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJhenAiOiJteV9jbGllbnRfaWQiLCJleHAiOjEzMTEyODE5NzAsImlhdCI6MTMxMTI4MDk3MCwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSByZWFkOnBhdGllbnRzIHJlYWQ6YWRtaW4ifQ.")
	assert.Error(t, err)
}
