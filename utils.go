package lib

import (
	"encoding/json"
	"fmt"
	"strings"

	http "github.com/taubyte/go-sdk/http/event"
	"golang.org/x/crypto/bcrypt"
)

// setCORSHeaders sets CORS headers for HTTP responses
func setCORSHeaders(h http.Event) {
	h.Headers().Set("Access-Control-Allow-Origin", "*")
	h.Headers().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	h.Headers().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

// sendJSONResponse sends a JSON response with status 200
func sendJSONResponse(h http.Event, data interface{}) uint32 {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return handleHTTPError(h, err, 500)
	}
	h.Headers().Set("Content-Type", "application/json")
	h.Write(jsonData)
	h.Return(200)
	return 0
}

// handleHTTPError handles HTTP errors and sends error response
func handleHTTPError(h http.Event, err error, code int) uint32 {
	h.Write([]byte(err.Error()))
	h.Return(code)
	return 1
}

// sendErrorResponse sends a JSON error response
func sendErrorResponse(h http.Event, message string, code int) uint32 {
	response := map[string]string{"error": message}
	jsonData, err := json.Marshal(response)
	if err != nil {
		h.Write([]byte("Internal server error"))
		h.Return(500)
		return 1
	}
	h.Headers().Set("Content-Type", "application/json")
	h.Write(jsonData)
	h.Return(code)
	return 1
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// comparePassword compares a password with a hash
func comparePassword(hashedPassword, password string) bool {
	fmt.Printf("DEBUG: comparePassword - hashed len: %d, plain len: %d\n", len(hashedPassword), len(password))
	
	// Validate hash format
	if len(hashedPassword) == 0 {
		fmt.Printf("DEBUG: Hashed password is empty!\n")
		return false
	}
	
	// Check if it's a valid bcrypt hash (should start with $2a$, $2b$, or $2y$)
	if len(hashedPassword) < 7 || (hashedPassword[:4] != "$2a$" && hashedPassword[:4] != "$2b$" && hashedPassword[:4] != "$2y$") {
		fmt.Printf("DEBUG: Invalid bcrypt hash format! Hash starts with: %s\n", hashedPassword[:min(10, len(hashedPassword))])
		return false
	}
	
	// Trim any potential whitespace
	hashedPassword = strings.TrimSpace(hashedPassword)
	
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Printf("DEBUG: Password comparison error: %v\n", err)
		return false
	}
	fmt.Printf("DEBUG: Password comparison succeeded\n")
	return true
}

