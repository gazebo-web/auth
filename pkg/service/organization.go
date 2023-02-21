package service

// Organization defines operations for organization business logic.
type Organization interface{}

// orgService is an implementation of the Organization interface.
type orgService struct{}

// NewOrganization configures and return a new Auth service instance.
func NewOrganization() Organization {
	return &orgService{}
}
