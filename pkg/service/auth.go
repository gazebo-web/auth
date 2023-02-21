package service

// Auth defines operations for auth business logic.
type Auth interface{}

// authService is an implementation of the Auth interface.
type authService struct{}

// NewAuth configures and return a new Auth service instance.
func NewAuth() Auth {
	return &authService{}
}
