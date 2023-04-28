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
			if len(h) == 0 {
				http.Error(w, "No bearer token provided. A bearer token is required to access this resource.", http.StatusBadRequest)
				return
			}
			hh := strings.Split(h, "Bearer ")
			if len(hh) != 2 {
				http.Error(w, "Invalid token", http.StatusBadRequest)
				return
			}
			token := hh[1]
			if len(token) == 0 {
				http.Error(w, "No bearer token provided", http.StatusBadRequest)
				return
			}
			err := auth.VerifyJWT(r.Context(), token)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to verify token: %s", err), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
