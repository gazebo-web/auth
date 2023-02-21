package service

// User defines operations for user business logic.
type User interface{}

// userService is an implementation of the User interface.
type userService struct{}

// NewUser configures and return a new User service instance.
func NewUser() User {
	return &userService{}
}
