package middleware

import (
	"fmt"
	"github.com/gazebo-web/auth/pkg/authentication"
	"net/http"
	"strings"
)

// BearerToken is an HTTP middleware that provides a token to any authentication.Authentication implementation.
// The token is extracted from the HTTP header called Authorization, including the prefix "Bearer ".
func BearerToken(auth authentication.Authentication) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			hh := strings.Split(h, "Bearer ")
			token := hh[1]
			err := auth.VerifyCredentials(r.Context(), authentication.Credentials{
				Scheme: authentication.SchemeBearer,
				Token:  token,
			})
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to verify token: %s", err), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
