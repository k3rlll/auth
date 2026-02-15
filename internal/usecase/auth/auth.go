package auth

import (
	"context"
	"errors"
	metrics "main/internal/metrics"
	"net/netip"
	"time"
	"unicode"

	"main/domain/entity"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthRepo defines the interface for authentication-related database operations.
type AuthRepo interface {
	// CreateUser creates a new user in the database with the provided details and returns the user ID.
	CreateUser(ctx context.Context, userID uuid.UUID, email, username, passwordHash string) (uuid.UUID, error)

	// GetUserByLogin retrieves the user ID and password hash based on the provided login (username or email).
	GetUserByLogin(ctx context.Context, login string) (userID uuid.UUID, passwordHash string, err error)

	// StoreSession saves the session associated with a user in the database, allowing for session management and token revocation.
	StoreSession(ctx context.Context, userID uuid.UUID, session entity.Session) error

	// DeleteSession removes a specific session for a user, effectively logging them out from that ONE SPECIFIC SESSION.
	DeleteSession(ctx context.Context, userID uuid.UUID, sessionID uuid.UUID) error

	// DeleteAllSessions removes all sessions associated with a user, effectively logging them out from !ALL! devices.
	DeleteAllSessions(ctx context.Context, userID uuid.UUID) error

	// UserIsBlocked checks if the user is blocked and returns true if the user is not blocked, false otherwise.
	UserIsBlocked(userID uuid.UUID) (bool, error)

	// GetSessionByRefreshToken retrieves the session information based on the provided refresh token.
	GetSessionByRefreshToken(ctx context.Context, refreshToken uuid.UUID) (entity.Session, error)

	// RefreshSession updates the session information in the database, allowing for token renewal and session extension.
	RefreshSession(ctx context.Context, session entity.Session) error
}

// JWTManager defines the interface for JWT token management.
type JWTManager interface {
	NewAccessToken(userID uuid.UUID) (string, error)
	VerifyAccessToken(token string) (userID uuid.UUID, err error)
}

type AuthUsecase struct {
	authRepo   AuthRepo
	JWTManager JWTManager
	Metrics    *metrics.Metrics
}

func NewAuthUsecase(authRepo AuthRepo, JWTManager JWTManager, metrics *metrics.Metrics) *AuthUsecase {
	return &AuthUsecase{
		authRepo:   authRepo,
		JWTManager: JWTManager,
		Metrics:    metrics,
	}
}

// RefreshSessionToken validates the provided refresh token and returns the associated user ID if the token is valid.
func (uc *AuthUsecase) RefreshSessionToken(ctx context.Context, refreshToken string) (string, string, error) {
	sid, err := uuid.Parse(refreshToken)
	if err != nil {
		return "", "", errors.New("invalid session ID")
	}

	session, err := uc.authRepo.GetSessionByRefreshToken(ctx, sid)
	if err != nil {
		return "", "", err
	}
	uid := session.UserID

	if session.ExpiresAt.Before(session.CreatedAt) {
		uc.authRepo.DeleteSession(ctx, uid, session.ID)
		return "", "", errors.New("session has expired")
	}

	session.ExpiresAt = time.Now().Add(15 * 24 * time.Hour)
	session.CreatedAt = time.Now()
	session.RefreshToken, err = uuid.NewUUID()
	if err != nil {
		return "", "", err
	}

	err = uc.authRepo.RefreshSession(ctx, session)
	if err != nil {
		return "", "", err
	}

	newAccessToken, err := uc.JWTManager.NewAccessToken(uid)
	if err != nil {
		return "", "", err
	}

	return newAccessToken, session.RefreshToken.String(), nil
}

// RegisterUser validates the input, hashes the password, and creates a new user in the database.
// It returns the user ID as a string or an error if the registration fails.
func (uc *AuthUsecase) RegisterUser(ctx context.Context, username, email, password string) (userID uuid.UUID, err error) {

	if !validateUsername(username) {
		return uuid.Nil, errors.New("username must be between 3 and 30 characters")
	}

	if !validateEmail(email) {
		return uuid.Nil, errors.New("invalid email format")
	}
	if err := validatePassword(password); err != nil {
		return uuid.Nil, err
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}
	userID, err = uuid.NewUUID()
	if err != nil {
		return uuid.Nil, err
	}

	return uc.authRepo.CreateUser(ctx, userID, email, username, passwordHash)

}

// LoginUser authenticates the user by verifying the provided credentials.
// If successful, it generates an access token and a refresh token, stores the session in the database, and returns the access token.
// If authentication fails, it returns an error.
func (uc *AuthUsecase) LoginUser(ctx context.Context,
	login,
	password,
	userAgent,
	ip string) (uuid.UUID, string, string, error) {

	userID, passwordHash, err := uc.authRepo.GetUserByLogin(ctx, login)
	if err != nil {
		uc.Metrics.LoginAttempts.WithLabelValues("failure").Inc()
		return uuid.Nil, "", "", err
	}
	if !verifyPassword(password, passwordHash) {
		uc.Metrics.LoginAttempts.WithLabelValues("failure").Inc()
		return uuid.Nil, "", "", errors.New("invalid credentials")
	}

	accessToken, err := uc.JWTManager.NewAccessToken(userID)
	if err != nil {
		uc.Metrics.LoginAttempts.WithLabelValues("failure").Inc()
		return uuid.Nil, "", "", err
	}

	refreshToken, err := uuid.NewUUID()
	if err != nil {
		uc.Metrics.LoginAttempts.WithLabelValues("failure").Inc()
		return uuid.Nil, "", "", err
	}

	netipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		uc.Metrics.LoginAttempts.WithLabelValues("failure").Inc()
		return uuid.Nil, "", "", errors.New("invalid IP address")
	}

	session := entity.Session{
		ID:           uuid.New(),
		UserID:       userID,
		RefreshToken: refreshToken,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(15 * 24 * time.Hour),
		UserAgent:    userAgent,
		ClientIP:     netipAddr,
	}

	err = uc.authRepo.StoreSession(ctx, userID, session)
	if err != nil {
		uc.Metrics.LoginAttempts.WithLabelValues("failure").Inc()
		return uuid.Nil, "", "", err
	}

	uc.Metrics.LoginAttempts.WithLabelValues("success").Inc()
	return userID, accessToken, refreshToken.String(), nil
}

// LogoutSession logs out the user from a specific session by deleting that session from the database.
func (uc *AuthUsecase) LogoutSession(ctx context.Context, userID string, sessionID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("invalid user ID")
	}
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		return errors.New("invalid session ID")
	}
	err = uc.authRepo.DeleteSession(ctx, uid, sid)
	if err != nil {
		return err
	}
	return nil
}

// LogoutAllSessions logs out the user from all sessions by deleting all sessions associated with the user from the database.
func (uc *AuthUsecase) LogoutAllSessions(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return errors.New("invalid user ID")
	}
	err = uc.authRepo.DeleteAllSessions(ctx, uid)
	if err != nil {
		return err
	}
	return nil
}

// VerifyUser checks if the provided access token is valid and returns the associated user ID if the token is valid.
// It also checks if the user is blocked and returns an error if the user is blocked.
func (uc *AuthUsecase) VerifyUser(token string) (userID uuid.UUID, err error) {
	userID, err = uc.JWTManager.VerifyAccessToken(token)
	if err != nil {
		return uuid.Nil, err
	}
	isBlocked, err := uc.authRepo.UserIsBlocked(userID)
	if err != nil {
		return uuid.Nil, err
	}
	if isBlocked {
		return uuid.Nil, errors.New("user is blocked")
	}
	return userID, nil
}

// hashPassword hashes the given password using bcrypt
func hashPassword(password string) (string, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(passwordHash), err
}

// verifyPassword compares the provided password with the stored password hash and returns true if they match, false otherwise.
func verifyPassword(password, passwordHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	return err == nil
}

// ValidatePassword checks if the password meets certain criteria
func validatePassword(password string) error {
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	if len(password) >= 8 {
		hasMinLen = true
	}

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasMinLen {
		return errors.New("password must be at least 8 characters long")
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// Simple function to check if a string contains '@' symbol
func containsAtSymbol(s string) bool {
	for _, char := range s {
		if char == '@' {
			return true
		}
	}
	return false
}

func validateEmail(email string) bool {
	// Simple email validation
	if len(email) < 5 || len(email) > 50 {
		return false
	}
	if !containsAtSymbol(email) {
		return false
	}
	return true
}

func validateUsername(username string) bool {
	if len(username) < 3 || len(username) > 30 {
		return false
	}
	return true
}

