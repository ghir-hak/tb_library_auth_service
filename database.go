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

	fmt.Printf("DEBUG: getUserByID - Retrieved password hash (len: %d): %s\n", 
		len(storageUser.Password), storageUser.Password)

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
	fmt.Printf("DEBUG: getUserByUsername called with username: '%s'\n", username)
	
	db, err := database.New("/data")
	if err != nil {
		fmt.Printf("DEBUG: Database connection failed: %v\n", err)
		return nil, fmt.Errorf("db connection failed: %w", err)
	}

	// Direct read - no index needed!
	key := fmt.Sprintf("%s%s", usersPrefix, username)
	fmt.Printf("DEBUG: Looking up key: '%s'\n", key)
	
	data, err := db.Get(key)
	if err != nil {
		fmt.Printf("DEBUG: Database Get failed for key '%s': %v\n", key, err)
		return nil, fmt.Errorf("user not found for username '%s': %w", username, err)
	}

	fmt.Printf("DEBUG: Data retrieved, length: %d bytes\n", len(data))
	fmt.Printf("DEBUG: Data preview (first 100 chars): %s\n", string(data[:min(100, len(data))]))

	var storageUser StorageUser
	if err := json.Unmarshal(data, &storageUser); err != nil {
		fmt.Printf("DEBUG: JSON unmarshal failed: %v\n", err)
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	fmt.Printf("DEBUG: Unmarshaled user - ID: %s, Username: %s, Email: %s, Password len: %d\n",
		storageUser.ID, storageUser.Username, storageUser.Email, len(storageUser.Password))
	fmt.Printf("DEBUG: Retrieved password hash: %s\n", storageUser.Password)
	fmt.Printf("DEBUG: Retrieved password hash bytes (hex): %x\n", []byte(storageUser.Password))

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
	fmt.Printf("DEBUG: saveUser called - ID: %s, Username: %s, Email: %s, Password len: %d\n",
		user.ID, user.Username, user.Email, len(user.Password))
	
	db, err := database.New("/data")
	if err != nil {
		fmt.Printf("DEBUG: Database connection failed: %v\n", err)
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
		fmt.Printf("DEBUG: JSON marshal failed: %v\n", err)
		return fmt.Errorf("failed to marshal user: %w", err)
	}

	fmt.Printf("DEBUG: Marshaled user data length: %d bytes\n", len(userData))
	fmt.Printf("DEBUG: Marshaled data includes password: %v\n", strings.Contains(string(userData), "password"))
	fmt.Printf("DEBUG: saveUser - Storing password hash (len: %d): %s\n", 
		len(storageUser.Password), storageUser.Password)
	fmt.Printf("DEBUG: saveUser - Password hash bytes (hex): %x\n", []byte(storageUser.Password))

	// Store by username (primary - for login)
	usernameKey := fmt.Sprintf("%s%s", usersPrefix, user.Username)
	fmt.Printf("DEBUG: Saving to username key: '%s'\n", usernameKey)
	if err := db.Put(usernameKey, userData); err != nil {
		fmt.Printf("DEBUG: Failed to save user by username: %v\n", err)
		return fmt.Errorf("failed to save user by username: %w", err)
	}
	fmt.Printf("DEBUG: Successfully saved to username key\n")

	// Store by ID (for JWT lookup)
	idKey := fmt.Sprintf("%s%s", usersByIDPrefix, user.ID)
	fmt.Printf("DEBUG: Saving to ID key: '%s'\n", idKey)
	if err := db.Put(idKey, userData); err != nil {
		fmt.Printf("DEBUG: Failed to save user by ID: %v\n", err)
		return fmt.Errorf("failed to save user by ID: %w", err)
	}
	fmt.Printf("DEBUG: Successfully saved to ID key\n")

	// Store email mapping (just username for uniqueness check and lookup)
	emailKey := fmt.Sprintf("%s%s", usersByEmailPrefix, user.Email)
	fmt.Printf("DEBUG: Saving email mapping to key: '%s' -> '%s'\n", emailKey, user.Username)
	if err := db.Put(emailKey, []byte(user.Username)); err != nil {
		fmt.Printf("DEBUG: Failed to save email mapping: %v\n", err)
		return fmt.Errorf("failed to save email mapping: %w", err)
	}
	fmt.Printf("DEBUG: Successfully saved email mapping\n")

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

