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

// TestDatabaseStorageAndRetrieval tests the exact data flow through database storage and retrieval
// This test verifies that the data type and content remain unchanged through the storage/retrieval cycle
func TestDatabaseStorageAndRetrieval(t *testing.T) {
	testPassword := "TestPassword123!@#"
	testUsername := "testuser_db"
	testEmail := "testdb@example.com"
	testID := "test-id-12345"
	
	fmt.Printf("\n=== TestDatabaseStorageAndRetrieval ===\n")
	fmt.Printf("Test password: %q (len=%d)\n", testPassword, len(testPassword))
	fmt.Printf("Test password bytes (hex): %x\n", []byte(testPassword))
	fmt.Printf("Test password bytes (decimal): %v\n", []byte(testPassword))
	
	// Step 1: Hash the password (simulating registration)
	fmt.Printf("\n--- Step 1: Hashing Password ---\n")
	hashedPassword, err := hashPassword(testPassword)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	fmt.Printf("Hashed password type: %T\n", hashedPassword)
	fmt.Printf("Hashed password value: %q\n", hashedPassword)
	fmt.Printf("Hashed password length: %d\n", len(hashedPassword))
	fmt.Printf("Hashed password bytes (hex): %x\n", []byte(hashedPassword))
	fmt.Printf("Hashed password bytes (decimal): %v\n", []byte(hashedPassword))
	
	// Step 2: Create User struct (what we have in memory before saving)
	fmt.Printf("\n--- Step 2: Creating User Struct ---\n")
	user := User{
		ID:       testID,
		Username: testUsername,
		Email:    testEmail,
		Password: hashedPassword,
	}
	fmt.Printf("User.Password type: %T\n", user.Password)
	fmt.Printf("User.Password value: %q\n", user.Password)
	fmt.Printf("User.Password length: %d\n", len(user.Password))
	fmt.Printf("User.Password bytes (hex): %x\n", []byte(user.Password))
	
	// Step 3: Convert to StorageUser (what gets stored)
	fmt.Printf("\n--- Step 3: Converting to StorageUser ---\n")
	storageUser := StorageUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
	}
	fmt.Printf("StorageUser.Password type: %T\n", storageUser.Password)
	fmt.Printf("StorageUser.Password value: %q\n", storageUser.Password)
	fmt.Printf("StorageUser.Password length: %d\n", len(storageUser.Password))
	fmt.Printf("StorageUser.Password bytes (hex): %x\n", []byte(storageUser.Password))
	
	// Verify they match
	if storageUser.Password != hashedPassword {
		t.Fatalf("StorageUser.Password != hashedPassword")
	}
	if len(storageUser.Password) != len(hashedPassword) {
		t.Fatalf("Password length mismatch: StorageUser=%d, Original=%d", 
			len(storageUser.Password), len(hashedPassword))
	}
	
	// Step 4: Marshal to JSON (what gets stored in database)
	fmt.Printf("\n--- Step 4: Marshaling to JSON (Database Storage) ---\n")
	userData, err := json.Marshal(storageUser)
	if err != nil {
		t.Fatalf("Failed to marshal user: %v", err)
	}
	fmt.Printf("Marshaled data type: %T\n", userData)
	fmt.Printf("Marshaled data length: %d bytes\n", len(userData))
	fmt.Printf("Marshaled data (string): %s\n", string(userData))
	fmt.Printf("Marshaled data (hex): %x\n", userData)
	fmt.Printf("Marshaled data (first 200 bytes as string): %s\n", 
		string(userData[:min(200, len(userData))]))
	
	// Extract password from JSON string to see how it's encoded
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(userData, &jsonMap); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}
	passwordFromJSON := jsonMap["password"].(string)
	fmt.Printf("\nPassword extracted from JSON map type: %T\n", passwordFromJSON)
	fmt.Printf("Password extracted from JSON map value: %q\n", passwordFromJSON)
	fmt.Printf("Password extracted from JSON map length: %d\n", len(passwordFromJSON))
	fmt.Printf("Password extracted from JSON map bytes (hex): %x\n", []byte(passwordFromJSON))
	
	// Verify password in JSON matches original
	if passwordFromJSON != hashedPassword {
		t.Fatalf("Password in JSON != original hash!\n  JSON: %q\n  Original: %q", 
			passwordFromJSON, hashedPassword)
	}
	
	// Step 5: Simulate database storage (store the bytes)
	fmt.Printf("\n--- Step 5: Simulating Database Storage ---\n")
	// In real scenario: db.Put(key, userData)
	storedBytes := make([]byte, len(userData))
	copy(storedBytes, userData)
	fmt.Printf("Stored bytes type: %T\n", storedBytes)
	fmt.Printf("Stored bytes length: %d\n", len(storedBytes))
	fmt.Printf("Stored bytes (hex): %x\n", storedBytes)
	
	// Verify stored bytes match marshaled data
	if len(storedBytes) != len(userData) {
		t.Fatalf("Stored bytes length mismatch: %d != %d", len(storedBytes), len(userData))
	}
	for i := 0; i < len(storedBytes); i++ {
		if storedBytes[i] != userData[i] {
			t.Fatalf("Stored bytes mismatch at position %d: %d != %d", i, storedBytes[i], userData[i])
		}
	}
	
	// Step 6: Simulate database retrieval (retrieve the bytes)
	fmt.Printf("\n--- Step 6: Simulating Database Retrieval ---\n")
	// In real scenario: data, err := db.Get(key)
	retrievedDataBytes := make([]byte, len(storedBytes))
	copy(retrievedDataBytes, storedBytes)
	fmt.Printf("Retrieved bytes type: %T\n", retrievedDataBytes)
	fmt.Printf("Retrieved bytes length: %d\n", len(retrievedDataBytes))
	fmt.Printf("Retrieved bytes (hex): %x\n", retrievedDataBytes)
	fmt.Printf("Retrieved bytes (string): %s\n", string(retrievedDataBytes))
	
	// Verify retrieved bytes match stored bytes
	if len(retrievedDataBytes) != len(storedBytes) {
		t.Fatalf("Retrieved bytes length mismatch: %d != %d", len(retrievedDataBytes), len(storedBytes))
	}
	for i := 0; i < len(retrievedDataBytes); i++ {
		if retrievedDataBytes[i] != storedBytes[i] {
			t.Fatalf("Retrieved bytes mismatch at position %d: %d != %d", 
				i, retrievedDataBytes[i], storedBytes[i])
		}
	}
	
	// Step 7: Unmarshal from JSON (what we get after retrieval)
	fmt.Printf("\n--- Step 7: Unmarshaling from JSON (Database Retrieval) ---\n")
	var retrievedStorageUser StorageUser
	if err := json.Unmarshal(retrievedDataBytes, &retrievedStorageUser); err != nil {
		t.Fatalf("Failed to unmarshal user: %v", err)
	}
	fmt.Printf("Retrieved StorageUser.Password type: %T\n", retrievedStorageUser.Password)
	fmt.Printf("Retrieved StorageUser.Password value: %q\n", retrievedStorageUser.Password)
	fmt.Printf("Retrieved StorageUser.Password length: %d\n", len(retrievedStorageUser.Password))
	fmt.Printf("Retrieved StorageUser.Password bytes (hex): %x\n", []byte(retrievedStorageUser.Password))
	fmt.Printf("Retrieved StorageUser.Password bytes (decimal): %v\n", []byte(retrievedStorageUser.Password))
	
	// Step 8: Convert back to User struct
	fmt.Printf("\n--- Step 8: Converting Back to User Struct ---\n")
	retrievedUser := User{
		ID:       retrievedStorageUser.ID,
		Username: retrievedStorageUser.Username,
		Email:    retrievedStorageUser.Email,
		Password: retrievedStorageUser.Password,
	}
	fmt.Printf("Retrieved User.Password type: %T\n", retrievedUser.Password)
	fmt.Printf("Retrieved User.Password value: %q\n", retrievedUser.Password)
	fmt.Printf("Retrieved User.Password length: %d\n", len(retrievedUser.Password))
	fmt.Printf("Retrieved User.Password bytes (hex): %x\n", []byte(retrievedUser.Password))
	
	// Step 9: Compare everything
	fmt.Printf("\n--- Step 9: Comparing All Values ---\n")
	
	// Compare original hash with retrieved hash
	fmt.Printf("Original hash: %q (len=%d)\n", hashedPassword, len(hashedPassword))
	fmt.Printf("Retrieved hash: %q (len=%d)\n", retrievedUser.Password, len(retrievedUser.Password))
	
	if retrievedUser.Password != hashedPassword {
		t.Fatalf("Password hash changed during storage/retrieval!\n  Original: %q\n  Retrieved: %q",
			hashedPassword, retrievedUser.Password)
	}
	
	if len(retrievedUser.Password) != len(hashedPassword) {
		t.Fatalf("Password hash length changed: Original=%d, Retrieved=%d",
			len(hashedPassword), len(retrievedUser.Password))
	}
	
	// Compare byte by byte
	originalPasswordBytes := []byte(hashedPassword)
	retrievedPasswordBytes := []byte(retrievedUser.Password)
	if len(originalPasswordBytes) != len(retrievedPasswordBytes) {
		t.Fatalf("Byte array length mismatch: %d != %d", len(originalPasswordBytes), len(retrievedPasswordBytes))
	}
	for i := 0; i < len(originalPasswordBytes); i++ {
		if originalPasswordBytes[i] != retrievedPasswordBytes[i] {
			t.Fatalf("Byte mismatch at position %d: Original=0x%02x (%d), Retrieved=0x%02x (%d)",
				i, originalPasswordBytes[i], originalPasswordBytes[i], retrievedPasswordBytes[i], retrievedPasswordBytes[i])
		}
	}
	
	// Step 10: Test password comparison with retrieved hash
	fmt.Printf("\n--- Step 10: Testing Password Comparison ---\n")
	if !comparePassword(retrievedUser.Password, testPassword) {
		t.Fatal("Password comparison failed with retrieved hash!")
	}
	fmt.Printf("Password comparison succeeded with retrieved hash!\n")
	
	// Final summary
	fmt.Printf("\n=== Test Summary ===\n")
	fmt.Printf("✓ Password hash type remains: %T\n", retrievedUser.Password)
	fmt.Printf("✓ Password hash value unchanged: %q\n", retrievedUser.Password)
	fmt.Printf("✓ Password hash length unchanged: %d\n", len(retrievedUser.Password))
	fmt.Printf("✓ All bytes match exactly\n")
	fmt.Printf("✓ Password comparison works with retrieved hash\n")
	fmt.Printf("=== Test Passed ===\n\n")
}

