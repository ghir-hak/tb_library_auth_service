package lib

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/taubyte/go-sdk/event"
	http "github.com/taubyte/go-sdk/http/event"
)

// authenticate extracts and validates JWT token from Authorization header
func authenticate(h http.Event) (string, uint32) {
	authHeader, err := h.Headers().Get("Authorization")
	if err != nil || authHeader == "" {
		return "", sendErrorResponse(h, "missing authorization header", 401)
	}

	// Extract token from "Bearer <token>"
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", sendErrorResponse(h, "invalid authorization format", 401)
	}

	tokenString := authHeader[7:]
	userID, err := ValidateToken(tokenString)
	if err != nil {
		return "", sendErrorResponse(h, "invalid or expired token", 401)
	}

	return userID, 0
}

//export register
func register(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req RegisterRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid request format", 400)
	}

	// Trim and validate required fields
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Password = strings.TrimSpace(req.Password)
	
	if req.Username == "" || req.Email == "" || req.Password == "" {
		return sendErrorResponse(h, "username, email, and password are required", 400)
	}

	// Check if user already exists
	exists, message, err := userExists(req.Username, req.Email)
	if err != nil {
		return sendErrorResponse(h, "failed to check user existence", 500)
	}
	if exists {
		return sendErrorResponse(h, message, 409)
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return sendErrorResponse(h, "failed to hash password", 500)
	}

	// Create user
	userID := fmt.Sprintf("%d", time.Now().UnixNano())
	user := User{
		ID:       userID,
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
	}

	// Save user
	if err := saveUser(user); err != nil {
		return sendErrorResponse(h, "failed to save user", 500)
	}

	// Return user without password
	userResponse := UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	return sendJSONResponse(h, userResponse)
}

//export login
func login(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Decode request body (consistent with register and updateUser handlers)
	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req LoginRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid request format", 400)
	}

	// Trim and validate required fields
	req.Username = strings.TrimSpace(req.Username)
	req.Password = strings.TrimSpace(req.Password)
	
	if req.Username == "" || req.Password == "" {
		return sendErrorResponse(h, "username and password are required", 400)
	}

	// Get user by username
	user, err := getUserByUsername(req.Username)
	if err != nil {
		// Don't expose internal error details - return generic invalid credentials message
		// Use same error message as password mismatch to prevent username enumeration
		return sendErrorResponse(h, "invalid credentials", 401)
	}

	// Verify password
	if !comparePassword(user.Password, req.Password) {
		return sendErrorResponse(h, "invalid credentials", 401)
	}

	// Generate token
	token, err := GenerateToken(user.ID)
	if err != nil {
		return sendErrorResponse(h, "failed to generate token", 500)
	}

	// Return token and user
	response := LoginResponse{
		Token: token,
		User: User{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
		},
	}

	return sendJSONResponse(h, response)
}

//export getUser
func getUser(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Authenticate
	userID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Get user
	user, err := getUserByID(userID)
	if err != nil {
		return sendErrorResponse(h, "user not found", 404)
	}

	// Return user without password
	userResponse := UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	return sendJSONResponse(h, userResponse)
}

//export updateUser
func updateUser(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate
	userID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req UpdateUserRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid request format", 400)
	}

	// Get user
	user, err := getUserByID(userID)
	if err != nil {
		return sendErrorResponse(h, "user not found", 404)
	}

	// Store original email to check if it changed
	originalEmail := user.Email
	emailWillChange := false

	// Update fields if provided
	if req.Email != "" {
		req.Email = strings.TrimSpace(req.Email)
		if req.Email == "" {
			return sendErrorResponse(h, "email cannot be empty", 400)
		}
		
		// Check if email is actually changing
		if req.Email != originalEmail {
			emailWillChange = true
			
			// Check if new email already exists (and not for this user)
			existingUser, err := getUserByEmail(req.Email)
			if err == nil && existingUser.ID != userID {
				return sendErrorResponse(h, "email already exists", 409)
			}
		}
		user.Email = req.Email
	}

	if req.Password != "" {
		req.Password = strings.TrimSpace(req.Password)
		if req.Password == "" {
			return sendErrorResponse(h, "password cannot be empty", 400)
		}
		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			return sendErrorResponse(h, "failed to hash password", 500)
		}
		user.Password = hashedPassword
	}

	// Save updated user first (this creates/updates the new email mapping)
	if err := saveUser(*user); err != nil {
		return sendErrorResponse(h, "failed to update user", 500)
	}

	// After successful save, delete old email mapping if email changed
	// This ensures atomicity: if save fails, old mapping remains; if save succeeds, we clean up old mapping
	if emailWillChange && originalEmail != "" {
		if err := deleteEmailMapping(originalEmail); err != nil {
			// Don't fail the update if deletion fails - the new mapping is already saved
			// This is a cleanup operation, not critical for the update to succeed
		}
	}

	// Return updated user without password
	userResponse := UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
	}

	return sendJSONResponse(h, userResponse)
}

//export deleteUser
func deleteUser(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Handle OPTIONS preflight request
	method, err := h.Method()
	if err == nil && method == "OPTIONS" {
		h.Return(200)
		return 0
	}

	// Authenticate
	userID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	// Delete user
	if err := deleteUserFromDB(userID); err != nil {
		return sendErrorResponse(h, "failed to delete user", 500)
	}

	response := map[string]string{"message": "user deleted successfully"}
	return sendJSONResponse(h, response)
}

//export test
func test(e event.Event) uint32 {
	h, err := e.HTTP()
	if err != nil {
		return 1
	}
	setCORSHeaders(h)

	// Test password storage and retrieval through actual Taubyte database
	testPassword := "TestPassword123!@#"
	testUsername := fmt.Sprintf("testuser_%d", time.Now().UnixNano())
	testEmail := fmt.Sprintf("test_%d@example.com", time.Now().UnixNano())
	testID := fmt.Sprintf("test-id-%d", time.Now().UnixNano())

	debugLog := []string{}
	addLog := func(msg string) {
		debugLog = append(debugLog, msg)
		fmt.Printf("TEST: %s\n", msg)
	}

	addLog("=== Starting Database Password Test ===")
	addLog(fmt.Sprintf("Test password: %q (len=%d)", testPassword, len(testPassword)))
	addLog(fmt.Sprintf("Test password bytes (hex): %x", []byte(testPassword)))
	addLog(fmt.Sprintf("Test username: %q", testUsername))
	addLog(fmt.Sprintf("Test email: %q", testEmail))
	addLog(fmt.Sprintf("Test ID: %q", testID))

	// Step 1: Hash the password
	addLog("\n--- Step 1: Hashing Password ---")
	hashedPassword, err := hashPassword(testPassword)
	if err != nil {
		addLog(fmt.Sprintf("ERROR: Failed to hash password: %v", err))
		return sendErrorResponse(h, fmt.Sprintf("Failed to hash password: %v", err), 500)
	}
	addLog(fmt.Sprintf("Hashed password type: %T", hashedPassword))
	addLog(fmt.Sprintf("Hashed password value: %q", hashedPassword))
	addLog(fmt.Sprintf("Hashed password length: %d", len(hashedPassword)))
	addLog(fmt.Sprintf("Hashed password bytes (hex): %x", []byte(hashedPassword)))

	// Step 2: Create User struct
	addLog("\n--- Step 2: Creating User Struct ---")
	user := User{
		ID:       testID,
		Username: testUsername,
		Email:    testEmail,
		Password: hashedPassword,
	}
	addLog(fmt.Sprintf("User.Password type: %T", user.Password))
	addLog(fmt.Sprintf("User.Password value: %q", user.Password))
	addLog(fmt.Sprintf("User.Password length: %d", len(user.Password)))
	addLog(fmt.Sprintf("User.Password bytes (hex): %x", []byte(user.Password)))

	// Step 3: Store user in database (ACTUAL DATABASE OPERATION)
	addLog("\n--- Step 3: Storing User in Database (saveUser) ---")
	addLog(fmt.Sprintf("Calling saveUser with username: %q", user.Username))
	err = saveUser(user)
	if err != nil {
		addLog(fmt.Sprintf("ERROR: Failed to save user: %v", err))
		return sendErrorResponse(h, fmt.Sprintf("Failed to save user: %v", err), 500)
	}
	addLog("✓ User saved successfully to database")

	// Step 4: Retrieve user from database by username (ACTUAL DATABASE OPERATION)
	addLog("\n--- Step 4: Retrieving User from Database by Username (getUserByUsername) ---")
	addLog(fmt.Sprintf("Calling getUserByUsername with username: %q", testUsername))
	retrievedUserByUsername, err := getUserByUsername(testUsername)
	if err != nil {
		addLog(fmt.Sprintf("ERROR: Failed to retrieve user by username: %v", err))
		return sendErrorResponse(h, fmt.Sprintf("Failed to retrieve user by username: %v", err), 500)
	}
	addLog("✓ User retrieved successfully from database by username")
	addLog(fmt.Sprintf("Retrieved User.Password type: %T", retrievedUserByUsername.Password))
	addLog(fmt.Sprintf("Retrieved User.Password value: %q", retrievedUserByUsername.Password))
	addLog(fmt.Sprintf("Retrieved User.Password length: %d", len(retrievedUserByUsername.Password)))
	addLog(fmt.Sprintf("Retrieved User.Password bytes (hex): %x", []byte(retrievedUserByUsername.Password)))
	addLog(fmt.Sprintf("Retrieved User.ID: %q", retrievedUserByUsername.ID))
	addLog(fmt.Sprintf("Retrieved User.Username: %q", retrievedUserByUsername.Username))
	addLog(fmt.Sprintf("Retrieved User.Email: %q", retrievedUserByUsername.Email))

	// Step 4b: Retrieve user from database by ID (ACTUAL DATABASE OPERATION)
	addLog("\n--- Step 4b: Retrieving User from Database by ID (getUserByID) ---")
	addLog(fmt.Sprintf("Calling getUserByID with ID: %q", testID))
	retrievedUserByID, err := getUserByID(testID)
	if err != nil {
		addLog(fmt.Sprintf("ERROR: Failed to retrieve user by ID: %v", err))
		return sendErrorResponse(h, fmt.Sprintf("Failed to retrieve user by ID: %v", err), 500)
	}
	addLog("✓ User retrieved successfully from database by ID")
	addLog(fmt.Sprintf("Retrieved by ID User.Password type: %T", retrievedUserByID.Password))
	addLog(fmt.Sprintf("Retrieved by ID User.Password value: %q", retrievedUserByID.Password))
	addLog(fmt.Sprintf("Retrieved by ID User.Password length: %d", len(retrievedUserByID.Password)))
	addLog(fmt.Sprintf("Retrieved by ID User.Password bytes (hex): %x", []byte(retrievedUserByID.Password)))
	addLog(fmt.Sprintf("Retrieved by ID User.ID: %q", retrievedUserByID.ID))
	addLog(fmt.Sprintf("Retrieved by ID User.Username: %q", retrievedUserByID.Username))
	addLog(fmt.Sprintf("Retrieved by ID User.Email: %q", retrievedUserByID.Email))

	// Verify both retrieval methods return the same data
	addLog("\n--- Step 4c: Verifying Both Retrieval Methods Return Same Data ---")
	usernameRetrievalMatch := retrievedUserByUsername.Password == retrievedUserByID.Password
	addLog(fmt.Sprintf("Password match between username and ID retrieval: %v", usernameRetrievalMatch))
	if !usernameRetrievalMatch {
		addLog("ERROR: Password differs between username and ID retrieval!")
		addLog(fmt.Sprintf("  Username retrieval: %q", retrievedUserByUsername.Password))
		addLog(fmt.Sprintf("  ID retrieval: %q", retrievedUserByID.Password))
	}

	// Use the username retrieval for further tests (both should be the same)
	retrievedUser := retrievedUserByUsername

	// Step 5: Compare original hash with retrieved hash
	addLog("\n--- Step 5: Comparing Original and Retrieved Hashes ---")
	addLog(fmt.Sprintf("Original hash: %q (len=%d)", hashedPassword, len(hashedPassword)))
	addLog(fmt.Sprintf("Retrieved hash: %q (len=%d)", retrievedUser.Password, len(retrievedUser.Password)))
	addLog(fmt.Sprintf("Original hash bytes (hex): %x", []byte(hashedPassword)))
	addLog(fmt.Sprintf("Retrieved hash bytes (hex): %x", []byte(retrievedUser.Password)))
	
	hashesMatch := retrievedUser.Password == hashedPassword
	addLog(fmt.Sprintf("String comparison (==): %v", hashesMatch))
	
	if !hashesMatch {
		addLog("ERROR: Password hash changed during storage/retrieval!")
		addLog(fmt.Sprintf("Original: %q", hashedPassword))
		addLog(fmt.Sprintf("Retrieved: %q", retrievedUser.Password))
	}

	lengthMatch := len(retrievedUser.Password) == len(hashedPassword)
	addLog(fmt.Sprintf("Length comparison: %v (Original=%d, Retrieved=%d)", 
		lengthMatch, len(hashedPassword), len(retrievedUser.Password)))

	// Byte-by-byte comparison
	originalBytes := []byte(hashedPassword)
	retrievedBytes := []byte(retrievedUser.Password)
	byteMismatches := 0
	mismatchPositions := []int{}
	
	if len(originalBytes) == len(retrievedBytes) {
		for i := 0; i < len(originalBytes); i++ {
			if originalBytes[i] != retrievedBytes[i] {
				byteMismatches++
				if len(mismatchPositions) < 10 {
					mismatchPositions = append(mismatchPositions, i)
				}
			}
		}
		addLog(fmt.Sprintf("Byte-by-byte comparison: %d mismatches found", byteMismatches))
		if byteMismatches > 0 {
			for _, pos := range mismatchPositions {
				addLog(fmt.Sprintf("  Mismatch at position %d: Original=0x%02x (%d), Retrieved=0x%02x (%d)",
					pos, originalBytes[pos], originalBytes[pos], retrievedBytes[pos], retrievedBytes[pos]))
			}
		}
	} else {
		addLog(fmt.Sprintf("ERROR: Byte array length mismatch: %d != %d", len(originalBytes), len(retrievedBytes)))
	}

	// Step 6: Test password comparison with retrieved hash
	addLog("\n--- Step 6: Testing Password Comparison ---")
	addLog(fmt.Sprintf("Retrieved hash: %q", retrievedUser.Password))
	addLog(fmt.Sprintf("Test password: %q", testPassword))
	addLog(fmt.Sprintf("Test password bytes (hex): %x", []byte(testPassword)))
	
	comparisonResult := comparePassword(retrievedUser.Password, testPassword)
	addLog(fmt.Sprintf("Password comparison result: %v", comparisonResult))

	if !comparisonResult {
		addLog("ERROR: Password comparison failed with retrieved hash!")
	}

	// Step 7: Verify all fields match
	addLog("\n--- Step 7: Verifying All User Fields ---")
	idMatch := retrievedUser.ID == user.ID
	usernameMatch := retrievedUser.Username == user.Username
	emailMatch := retrievedUser.Email == user.Email
	
	addLog(fmt.Sprintf("ID match: %v (Original=%q, Retrieved=%q)", idMatch, user.ID, retrievedUser.ID))
	addLog(fmt.Sprintf("Username match: %v (Original=%q, Retrieved=%q)", usernameMatch, user.Username, retrievedUser.Username))
	addLog(fmt.Sprintf("Email match: %v (Original=%q, Retrieved=%q)", emailMatch, user.Email, retrievedUser.Email))

	// Prepare response
	response := map[string]interface{}{
		"message": "Database password test completed",
		"test": map[string]interface{}{
			"username": testUsername,
			"email":    testEmail,
			"id":       testID,
		},
		"results": map[string]interface{}{
			"password_hash_stored":                hashedPassword,
			"password_hash_retrieved_by_username": retrievedUserByUsername.Password,
			"password_hash_retrieved_by_id":       retrievedUserByID.Password,
			"username_id_retrieval_match":         usernameRetrievalMatch,
			"hashes_match":                        hashesMatch,
			"length_match":                        lengthMatch,
			"byte_mismatches":                     byteMismatches,
			"password_comparison":                 comparisonResult,
			"id_match":                            idMatch,
			"username_match":                      usernameMatch,
			"email_match":                         emailMatch,
		},
		"debug_log": debugLog,
		"summary": map[string]interface{}{
			"success":                hashesMatch && lengthMatch && comparisonResult && idMatch && usernameMatch && emailMatch,
			"password_hash_preserved": hashesMatch && lengthMatch && byteMismatches == 0,
			"password_comparison_works": comparisonResult,
			"all_fields_match":       idMatch && usernameMatch && emailMatch,
		},
	}

	return sendJSONResponse(h, response)
}

