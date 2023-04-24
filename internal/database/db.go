package database

import (
	"github.com/gazebo-web/auth/pkg/domain"
	gormUtils "github.com/gazebo-web/gz-go/v7/database/gorm"
	"github.com/jinzhu/gorm"
)

// SetupTestDB initializes a gorm.DB connection with a testing database.
// The test database name will have "_test" appended to it before attempting to connect.
func SetupTestDB() (*gorm.DB, error) {
	return gormUtils.GetTestDBFromEnvVars()
}

// SetupDB initializes a gorm.DB connection with a production database.
// Refer to the GetDBFromEnvVars function in the  to see configuration environment variables.
func SetupDB() (*gorm.DB, error) {
	return gormUtils.GetDBFromEnvVars()
}

// DropTables drops all tables from the given database. Usually used on tests to drop all data created after each test.
func DropTables(db *gorm.DB) error {
	return db.DropTableIfExists(
		&domain.Organization{},
		&domain.User{},
	).Error
}

// MigrateTables migrates all tables on the given database.
// Usually called after setting a database connection up with SetupDB or SetupTestDB.
func MigrateTables(db *gorm.DB) error {
	return db.AutoMigrate(
		&domain.User{},
		&domain.Organization{},
	).Error
}
