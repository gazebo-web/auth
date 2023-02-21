package domain

import "github.com/jinzhu/gorm"

// Organization groups users and resources under a single collective identity and allows managing permissions in
// collective fashion.
type Organization struct {
	gorm.Model
}

// TableName defines the model's SQL table name.
func (u Organization) TableName() string {
	return "organizations"
}

// GetID returns the unique identifier for a persisted model entry.
// A zero-value is returned if the model is not persisted yet.
func (u Organization) GetID() uint {
	return u.ID
}
