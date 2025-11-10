package lib

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/taubyte/go-sdk/database"
)

const (
	usersPrefix      = "/users/"
	usersByIDPrefix  = "/users/id/"
	usersByEmailPrefix = "/users/email/"
)

// getUserByID retrieves a user by ID from the database
// SIMPLE: Direct lookup by ID
func getUserByID(id string) (*User, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, err
	}

	data, err := db.Get(fmt.Sprintf("%s%s", usersByIDPrefix, id))
	if err != nil {
		return nil, fmt.Errorf("user not found for ID '%s': %w", id, err)
	}

	var storageUser StorageUser
	if err := json.Unmarshal(data, &storageUser); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	user := User{
		ID:       storageUser.ID,
		Username: storageUser.Username,
		Email:    storageUser.Email,
		Password: storageUser.Password,
	}

	return &user, nil
}

// getUserByUsername retrieves a user by username from the database
// SIMPLE: Direct lookup by username, no index needed
func getUserByUsername(username string) (*User, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, fmt.Errorf("db connection failed: %w", err)
	}

	// Direct read - no index needed!
	key := fmt.Sprintf("%s%s", usersPrefix, username)
	
	data, err := db.Get(key)
	if err != nil {
		return nil, fmt.Errorf("user not found for username '%s': %w", username, err)
	}

	var storageUser StorageUser
	if err := json.Unmarshal(data, &storageUser); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	user := User{
		ID:       storageUser.ID,
		Username: storageUser.Username,
		Email:    storageUser.Email,
		Password: storageUser.Password,
	}

	return &user, nil
}

// getUserByEmail retrieves a user by email from the database
// SIMPLE: Read email mapping to get username, then read user
func getUserByEmail(email string) (*User, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, err
	}

	// Get username from email mapping
	usernameData, err := db.Get(fmt.Sprintf("%s%s", usersByEmailPrefix, email))
	if err != nil {
		return nil, fmt.Errorf("email not found: %w", err)
	}

	username := strings.TrimSpace(string(usernameData))
	if username == "" {
		return nil, fmt.Errorf("empty username from email mapping")
	}

	// Get user by username
	return getUserByUsername(username)
}

// saveUser saves a user to the database
// SIMPLE: Store in multiple places for easy lookup
func saveUser(user User) error {
	db, err := database.New("/data")
	if err != nil {
		return fmt.Errorf("db connection failed: %w", err)
	}

	// Convert to storage user (includes password)
	storageUser := StorageUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
	}

	// Serialize storage user (includes password)
	userData, err := json.Marshal(storageUser)
	if err != nil {
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	// Store by username (primary - for login)
	usernameKey := fmt.Sprintf("%s%s", usersPrefix, user.Username)
	if err := db.Put(usernameKey, userData); err != nil {
		return fmt.Errorf("failed to save user by username: %w", err)
	}

	// Store by ID (for JWT lookup)
	idKey := fmt.Sprintf("%s%s", usersByIDPrefix, user.ID)
	if err := db.Put(idKey, userData); err != nil {
		return fmt.Errorf("failed to save user by ID: %w", err)
	}

	// Store email mapping (just username for uniqueness check and lookup)
	emailKey := fmt.Sprintf("%s%s", usersByEmailPrefix, user.Email)
	if err := db.Put(emailKey, []byte(user.Username)); err != nil {
		return fmt.Errorf("failed to save email mapping: %w", err)
	}

	return nil
}

// deleteEmailMapping deletes an email mapping from the database
func deleteEmailMapping(email string) error {
	db, err := database.New("/data")
	if err != nil {
		return fmt.Errorf("db connection failed: %w", err)
	}

	emailKey := fmt.Sprintf("%s%s", usersByEmailPrefix, email)
	if err := db.Delete(emailKey); err != nil {
		return fmt.Errorf("failed to delete email mapping: %w", err)
	}
	return nil
}

// deleteUserFromDB deletes a user from the database
// SIMPLE: Delete from all storage locations
func deleteUserFromDB(id string) error {
	db, err := database.New("/data")
	if err != nil {
		return err
	}

	// Get user by ID first to get username and email
	userData, err := db.Get(fmt.Sprintf("%s%s", usersByIDPrefix, id))
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	var storageUser StorageUser
	if err := json.Unmarshal(userData, &storageUser); err != nil {
		return fmt.Errorf("failed to unmarshal user: %w", err)
	}

	user := User{
		ID:       storageUser.ID,
		Username: storageUser.Username,
		Email:    storageUser.Email,
		Password: storageUser.Password,
	}

	// Delete from all locations
	if err := db.Delete(fmt.Sprintf("%s%s", usersPrefix, user.Username)); err != nil {
		return fmt.Errorf("failed to delete user by username: %w", err)
	}

	if err := db.Delete(fmt.Sprintf("%s%s", usersByIDPrefix, user.ID)); err != nil {
		return fmt.Errorf("failed to delete user by ID: %w", err)
	}

	if err := db.Delete(fmt.Sprintf("%s%s", usersByEmailPrefix, user.Email)); err != nil {
		return fmt.Errorf("failed to delete email mapping: %w", err)
	}

	return nil
}

// userExists checks if a username or email already exists
// SIMPLE: Just check if keys exist
func userExists(username, email string) (bool, string, error) {
	db, err := database.New("/data")
	if err != nil {
		return false, "", err
	}

	// Check username (direct lookup)
	_, err = db.Get(fmt.Sprintf("%s%s", usersPrefix, username))
	if err == nil {
		return true, "username already exists", nil
	}

	// Check email (via email mapping)
	_, err = db.Get(fmt.Sprintf("%s%s", usersByEmailPrefix, email))
	if err == nil {
		return true, "email already exists", nil
	}

	return false, "", nil
}

