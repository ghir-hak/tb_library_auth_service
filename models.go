package lib

// User represents a user in the system (password excluded from JSON)
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"` // Never serialize password in responses
}

// StorageUser is used for database storage (includes password)
type StorageUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest represents the request body for user registration
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents the request body for user login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UpdateUserRequest represents the request body for updating user
type UpdateUserRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
}

// LoginResponse represents the response for successful login
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// UserResponse represents a user response (without password)
type UserResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

