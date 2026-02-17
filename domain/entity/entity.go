package entity

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system with essential attributes.
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password"`
	CreatedAt    time.Time `json:"created_at"`
	IsBlocked    bool      `json:"is_blocked"`
}

// Session represents a user session with relevant details for authentication and tracking.
type Session struct {
	ID           uuid.UUID  `json:"id"`
	UserID       uuid.UUID  `json:"user_id"`
	RefreshToken uuid.UUID  `json:"refresh_token"`
	IsBlocked    bool       `json:"is_blocked"`
	ClientIP     netip.Addr `json:"client_ip"`
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	UserAgent    string     `json:"user_agent"`
}
