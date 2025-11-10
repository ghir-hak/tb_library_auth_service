package lib

import (
	"encoding/json"
	"fmt"
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

	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req RegisterRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, err.Error(), 400)
	}

	// Validate required fields
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

	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req LoginRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, err.Error(), 400)
	}

	// Validate required fields
	if req.Username == "" || req.Password == "" {
		return sendErrorResponse(h, "username and password are required", 400)
	}

	// Get user by username
	user, err := getUserByUsername(req.Username)
	if err != nil {
		// Return detailed error for debugging
		return sendErrorResponse(h, fmt.Sprintf("getUserByUsername failed: %v", err), 401)
	}

	// Verify password
	if !comparePassword(user.Password, req.Password) {
		return sendErrorResponse(h, "invalid credentials - password mismatch", 401)
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

	// Authenticate
	userID, retCode := authenticate(h)
	if retCode != 0 {
		return retCode
	}

	reqDec := json.NewDecoder(h.Body())
	defer h.Body().Close()

	var req UpdateUserRequest
	if err := reqDec.Decode(&req); err != nil {
		return sendErrorResponse(h, "invalid JSON", 400)
	}

	// Get user
	user, err := getUserByID(userID)
	if err != nil {
		return sendErrorResponse(h, "user not found", 404)
	}

	// Update fields if provided
	if req.Email != "" {
		// Check if email already exists (and not for this user)
		existingUser, err := getUserByEmail(req.Email)
		if err == nil && existingUser.ID != userID {
			return sendErrorResponse(h, "email already exists", 409)
		}
		user.Email = req.Email
	}

	if req.Password != "" {
		hashedPassword, err := hashPassword(req.Password)
		if err != nil {
			return sendErrorResponse(h, "failed to hash password", 500)
		}
		user.Password = hashedPassword
	}

	// Save updated user
	if err := saveUser(*user); err != nil {
		return sendErrorResponse(h, "failed to update user", 500)
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

