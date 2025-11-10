package lib

import (
	"encoding/json"
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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// comparePassword compares a password with a hash
// Note: Password should already be trimmed by the calling handler, but we trim the hash
// as a safety measure in case it has any encoding issues from storage
func comparePassword(hashedPassword, password string) bool {
	// Trim whitespace from hash to handle any encoding/storage issues
	hashedPassword = strings.TrimSpace(hashedPassword)
	
	// Validate inputs
	if len(hashedPassword) == 0 || len(password) == 0 {
		return false
	}
	
	// Validate hash prefix (bcrypt hashes start with $2a$, $2b$, or $2y$)
	if !strings.HasPrefix(hashedPassword, "$2a$") && 
	   !strings.HasPrefix(hashedPassword, "$2b$") && 
	   !strings.HasPrefix(hashedPassword, "$2y$") {
		return false
	}
	
	// Compare using bcrypt
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

