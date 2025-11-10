package lib

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Test password hashing and comparison
func TestPasswordHashing(t *testing.T) {
	testPassword := "mySecurePassword123"
	
	// Test 1: Hash password
	hashedPassword, err := hashPassword(testPassword)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	if hashedPassword == "" {
		t.Fatal("Hashed password is empty")
	}
	
	fmt.Printf("Test 1: Hashed password length: %d\n", len(hashedPassword))
	fmt.Printf("Test 1: Hashed password (first 60 chars): %s\n", hashedPassword[:min(60, len(hashedPassword))])
	
	// Test 2: Compare correct password
	if !comparePassword(hashedPassword, testPassword) {
		t.Fatal("Password comparison failed for correct password")
	}
	fmt.Printf("Test 2: Password comparison succeeded for correct password\n")
	
	// Test 3: Compare wrong password
	if comparePassword(hashedPassword, "wrongPassword") {
		t.Fatal("Password comparison should have failed for wrong password")
	}
	fmt.Printf("Test 3: Password comparison correctly rejected wrong password\n")
	
	// Test 4: Test with whitespace (leading/trailing)
	// Since we trim passwords before hashing and comparison, passwords with spaces
	// should be treated the same as passwords without spaces
	passwordWithSpaces := "  mySecurePassword123  "
	passwordTrimmed := strings.TrimSpace(passwordWithSpaces)
	
	// Hash the trimmed password (simulating registration behavior)
	hashedPasswordSpaces, err := hashPassword(passwordTrimmed)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	// Compare with original (no spaces) - should succeed because both get trimmed
	if !comparePassword(hashedPasswordSpaces, testPassword) {
		t.Fatal("Password comparison should work when both passwords trim to the same value")
	}
	
	// Compare with spaces - should succeed because input gets trimmed
	if !comparePassword(hashedPasswordSpaces, passwordWithSpaces) {
		t.Fatal("Password with spaces should match after trimming")
	}
	fmt.Printf("Test 4: Whitespace handling works correctly (passwords are trimmed)\n")
}

// Test password storage and retrieval simulation
func TestPasswordStorageRetrieval(t *testing.T) {
	testPassword := "testPassword123"
	hashedPassword, err := hashPassword(testPassword)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	
	// Simulate storing in database (JSON marshaling)
	storageUser := StorageUser{
		ID:       "test-id",
		Username: "testuser",
		Email:    "test@example.com",
		Password: hashedPassword,
	}
	
	userData, err := json.Marshal(storageUser)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}
	
	fmt.Printf("Test Storage: Marshaled data length: %d bytes\n", len(userData))
	fmt.Printf("Test Storage: Marshaled data (first 200 chars): %s\n", string(userData[:min(200, len(userData))]))
	
	// Simulate retrieving from database (JSON unmarshaling)
	var retrievedUser StorageUser
	if err := json.Unmarshal(userData, &retrievedUser); err != nil {
		t.Fatalf("Failed to unmarshal user: %v", err)
	}
	
	fmt.Printf("Test Storage: Retrieved password length: %d\n", len(retrievedUser.Password))
	fmt.Printf("Test Storage: Retrieved password (first 60 chars): %s\n", retrievedUser.Password[:min(60, len(retrievedUser.Password))])
	fmt.Printf("Test Storage: Original password (first 60 chars): %s\n", hashedPassword[:min(60, len(hashedPassword))])
	
	// Check if passwords match
	if retrievedUser.Password != hashedPassword {
		t.Fatalf("Password changed during storage/retrieval! Original len: %d, Retrieved len: %d", 
			len(hashedPassword), len(retrievedUser.Password))
	}
	
	// Test comparison after retrieval
	if !comparePassword(retrievedUser.Password, testPassword) {
		t.Fatal("Password comparison failed after storage/retrieval simulation")
	}
	fmt.Printf("Test Storage: Password comparison succeeded after storage/retrieval\n")
}

// Test edge cases
func TestPasswordEdgeCases(t *testing.T) {
	// Test empty password
	_, err := hashPassword("")
	if err != nil {
		t.Fatalf("Should be able to hash empty password: %v", err)
	}
	
	// Test very long password
	longPassword := ""
	for i := 0; i < 1000; i++ {
		longPassword += "a"
	}
	hashedLong, err := hashPassword(longPassword)
	if err != nil {
		t.Fatalf("Failed to hash long password: %v", err)
	}
	if !comparePassword(hashedLong, longPassword) {
		t.Fatal("Failed to compare long password")
	}
	fmt.Printf("Test Edge Cases: Long password handled correctly\n")
	
	// Test special characters
	specialPassword := "!@#$%^&*()_+-=[]{}|;':\",./<>?"
	hashedSpecial, err := hashPassword(specialPassword)
	if err != nil {
		t.Fatalf("Failed to hash special character password: %v", err)
	}
	if !comparePassword(hashedSpecial, specialPassword) {
		t.Fatal("Failed to compare special character password")
	}
	fmt.Printf("Test Edge Cases: Special characters handled correctly\n")
}

