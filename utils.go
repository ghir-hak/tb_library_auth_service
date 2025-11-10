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
	fmt.Printf("DEBUG: hashPassword - Hashing password (length: %d, first 10 chars: %s)\n", 
		len(password), password[:min(10, len(password))])
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		fmt.Printf("DEBUG: hashPassword - Failed to generate hash: %v\n", err)
		return "", err
	}
	hashed := string(bytes)
	fmt.Printf("DEBUG: hashPassword - Generated hash (length: %d): %s\n", len(hashed), hashed)
	fmt.Printf("DEBUG: hashPassword - Hash bytes (hex): %x\n", bytes)
	return hashed, nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// comparePassword compares a password with a hash
func comparePassword(hashedPassword, password string) bool {
	// Trim whitespace from both inputs to handle any encoding/storage issues
	hashedPassword = strings.TrimSpace(hashedPassword)
	password = strings.TrimSpace(password)
	
	// Validate inputs
	if len(hashedPassword) == 0 {
		fmt.Printf("DEBUG: comparePassword - Hashed password is empty!\n")
		return false
	}
	
	if len(password) == 0 {
		fmt.Printf("DEBUG: comparePassword - Plain password is empty!\n")
		return false
	}
	
	// Validate bcrypt hash format - should start with $2a$, $2b$, or $2y$ and be 60 chars
	if len(hashedPassword) != 60 {
		fmt.Printf("DEBUG: comparePassword - Invalid hash length: %d (expected 60)\n", len(hashedPassword))
		// Still try to compare in case it's a valid hash with different length (unlikely)
	}
	
	// Validate hash prefix (bcrypt hashes start with $2a$, $2b$, or $2y$)
	if !strings.HasPrefix(hashedPassword, "$2a$") && 
	   !strings.HasPrefix(hashedPassword, "$2b$") && 
	   !strings.HasPrefix(hashedPassword, "$2y$") {
		fmt.Printf("DEBUG: comparePassword - Invalid hash format! Hash prefix: %s\n", 
			hashedPassword[:min(10, len(hashedPassword))])
		return false
	}
	
	fmt.Printf("DEBUG: comparePassword - hashed len: %d, plain len: %d, hash prefix: %s\n", 
		len(hashedPassword), len(password), hashedPassword[:min(7, len(hashedPassword))])
	fmt.Printf("DEBUG: comparePassword - FULL HASH: %s\n", hashedPassword)
	fmt.Printf("DEBUG: comparePassword - Hash bytes (hex): %x\n", []byte(hashedPassword))
	fmt.Printf("DEBUG: comparePassword - Plain password (first 10 chars): %s\n", 
		password[:min(10, len(password))])
	
	// Compare using bcrypt - this is the authoritative check
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Printf("DEBUG: comparePassword - bcrypt comparison failed: %v\n", err)
		fmt.Printf("DEBUG: comparePassword - Hash that failed: %s\n", hashedPassword)
		return false
	}
	
	fmt.Printf("DEBUG: comparePassword - Password comparison succeeded\n")
	return true
}

