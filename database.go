package lib

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/taubyte/go-sdk/database"
)

const (
	usersPrefix      = "/users/"
	usernameIndexPrefix = "/users/by-username/"
	emailIndexPrefix    = "/users/by-email/"
)

// getUserByID retrieves a user by ID from the database
func getUserByID(id string) (*User, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, err
	}

	data, err := db.Get(fmt.Sprintf("%s%s", usersPrefix, id))
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// getUserByUsername retrieves a user by username from the database
func getUserByUsername(username string) (*User, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, fmt.Errorf("STEP 0: db connection failed: %w", err)
	}

	// Step 1: Get user ID from username index
	usernameKey := fmt.Sprintf("%s%s", usernameIndexPrefix, username)
	userIDData, err := db.Get(usernameKey)
	if err != nil {
		return nil, fmt.Errorf("STEP 1 FAILED: username index lookup - key: '%s', username: '%s', error: %w", usernameKey, username, err)
	}

	// Step 2: Convert bytes to string and clean it
	userID := string(userIDData)
	userID = strings.TrimSpace(userID)
	userID = strings.TrimRight(userID, "\x00")
	if userID == "" {
		return nil, fmt.Errorf("STEP 2 FAILED: empty userID from index - raw bytes: %v, len: %d", userIDData, len(userIDData))
	}

	// Step 3: Get user data using the userID
	userKey := fmt.Sprintf("%s%s", usersPrefix, userID)
	data, err := db.Get(userKey)
	if err != nil {
		return nil, fmt.Errorf("STEP 3 FAILED: user data lookup - userID: '%s' (len=%d), key: '%s', error: %w", userID, len(userID), userKey, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("STEP 3 FAILED: empty user data - userID: '%s', key: '%s'", userID, userKey)
	}

	// Step 4: Unmarshal user data
	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("STEP 4 FAILED: json unmarshal - userID: '%s', data len: %d, data preview: %s, error: %w", userID, len(data), string(data[:min(50, len(data))]), err)
	}

	return &user, nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getUserByEmail retrieves a user by email from the database
func getUserByEmail(email string) (*User, error) {
	db, err := database.New("/data")
	if err != nil {
		return nil, err
	}

	// Get user ID from email index
	userIDData, err := db.Get(fmt.Sprintf("%s%s", emailIndexPrefix, email))
	if err != nil {
		return nil, err
	}

	userID := string(userIDData)

	// Get user data using the same connection
	data, err := db.Get(fmt.Sprintf("%s%s", usersPrefix, userID))
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, err
	}

	return &user, nil
}

// saveUser saves a user to the database
func saveUser(user User) error {
	db, err := database.New("/data")
	if err != nil {
		return err
	}

	// Serialize user
	userData, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// Save user
	userKey := fmt.Sprintf("%s%s", usersPrefix, user.ID)
	if err := db.Put(userKey, userData); err != nil {
		return err
	}

	// Save username index
	usernameKey := fmt.Sprintf("%s%s", usernameIndexPrefix, user.Username)
	if err := db.Put(usernameKey, []byte(user.ID)); err != nil {
		return err
	}

	// Save email index
	emailKey := fmt.Sprintf("%s%s", emailIndexPrefix, user.Email)
	if err := db.Put(emailKey, []byte(user.ID)); err != nil {
		return err
	}

	return nil
}

// deleteUserFromDB deletes a user from the database
func deleteUserFromDB(id string) error {
	db, err := database.New("/data")
	if err != nil {
		return err
	}

	// Get user first to delete indexes
	userData, err := db.Get(fmt.Sprintf("%s%s", usersPrefix, id))
	if err != nil {
		return err
	}

	var user User
	if err := json.Unmarshal(userData, &user); err != nil {
		return err
	}

	// Delete user
	userKey := fmt.Sprintf("%s%s", usersPrefix, id)
	if err := db.Delete(userKey); err != nil {
		return err
	}

	// Delete username index
	usernameKey := fmt.Sprintf("%s%s", usernameIndexPrefix, user.Username)
	if err := db.Delete(usernameKey); err != nil {
		return err
	}

	// Delete email index
	emailKey := fmt.Sprintf("%s%s", emailIndexPrefix, user.Email)
	if err := db.Delete(emailKey); err != nil {
		return err
	}

	return nil
}

// userExists checks if a username or email already exists
func userExists(username, email string) (bool, string, error) {
	db, err := database.New("/data")
	if err != nil {
		return false, "", err
	}

	// Check username
	_, err = db.Get(fmt.Sprintf("%s%s", usernameIndexPrefix, username))
	if err == nil {
		return true, "username already exists", nil
	}

	// Check email
	_, err = db.Get(fmt.Sprintf("%s%s", emailIndexPrefix, email))
	if err == nil {
		return true, "email already exists", nil
	}

	return false, "", nil
}

