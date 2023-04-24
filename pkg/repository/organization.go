package repository

import (
	"github.com/gazebo-web/auth/pkg/domain"
	"github.com/gazebo-web/gz-go/v7/repository"
	"github.com/jinzhu/gorm"
)

// NewOrganization returns a repository.Repository instance configured to interact with the Organization
// domain model.
func NewOrganization(db *gorm.DB) repository.Repository {
	return repository.NewRepository(db, domain.User{})
}
