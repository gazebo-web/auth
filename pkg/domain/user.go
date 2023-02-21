package domain

import "github.com/jinzhu/gorm"

// User represents a unique identity that can own and create resources.
type User struct {
	gorm.Model
}

// TableName defines the model's SQL table name.
func (u User) TableName() string {
	return "users"
}

// GetID returns the unique identifier for a persisted model entry.
// A zero-value is returned if the model is not persisted yet.
func (u User) GetID() uint {
	return u.ID
}
