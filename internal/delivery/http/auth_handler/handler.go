package authHandler

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	AuthUsecase AuthUsecase
}

type AuthUsecase interface {

	//RegisterUser registers a new user and returns the user ID as a string.
	RegisterUser(ctx context.Context, username, email, password string) (userID uuid.UUID, err error)

	//LoginUser authenticates a user and returns the user ID, access token, and refresh token.
	LoginUser(ctx context.Context, login, password, userAgent string, ip string) (userID uuid.UUID, accessToken string, refreshToken string, err error)

	//LogoutSession logs out a user from a specific session.
	LogoutSession(ctx context.Context, userID string, sessionID string) error

	//LogoutAllSessions logs out a user from all sessions.
	LogoutAllSessions(ctx context.Context, userID string) error

	//RefreshSessionToken refreshes the access token using a valid refresh token and returns the new access token and refresh token.
	RefreshSessionToken(ctx context.Context, refreshToken string) (newAccessToken string, newRefreshToken string, err error)
}

func NewAuthHandler(authUsecase AuthUsecase) *AuthHandler {
	return &AuthHandler{AuthUsecase: authUsecase}
}

// DTOs
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type LogoutRequest struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

func (h *AuthHandler) Register(c echo.Context) error {
	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
	}
	userID, err := h.AuthUsecase.RegisterUser(c.Request().Context(), req.Username, req.Email, req.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to register user: %v", err))
	}
	return c.JSON(201, map[string]string{"user_id": userID.String()})
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
	}
	userID, accessToken, refreshToken, err := h.AuthUsecase.LoginUser(
		c.Request().Context(),
		req.Login,
		req.Password,
		c.Request().UserAgent(),
		c.RealIP())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, fmt.Sprintf("invalid credentials: %v", err))
	}

	cookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(15 * 24 * time.Hour),
		Path:     "/",
		// could add SameSite attribute if needed
		// could add another sites for different environments (e.g., development vs production)
	}

	c.SetCookie(cookie)
	c.Set("user_id", userID) // Store user ID in context for later use (e.g., in refresh handler)

	return c.JSON(200, map[string]string{"access_token": accessToken})

}

// Logout handles the logout request by invalidating the specified session for the user.
// It expects a JSON payload containing the user ID and session ID. If the request is valid and the session is successfully invalidated,
// it returns a 204 No Content response. If there are any errors during the process, it returns an appropriate HTTP error response.
func (h *AuthHandler) Logout(c echo.Context) error {
	var req LogoutRequest

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
	}
	err := h.AuthUsecase.LogoutSession(c.Request().Context(), req.UserID, req.SessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to logout session: %v", err))
	}

	return c.NoContent(204)
}

// LogoutAll handles the logout request by invalidating all sessions for the user.
func (h *AuthHandler) LogoutAll(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("invalid request: %v", err))
	}
	err := h.AuthUsecase.LogoutAllSessions(c.Request().Context(), req.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to logout all sessions: %v", err))
	}

	c.SetCookie(
		&http.Cookie{
			Name:     "refresh_token",
			Value:    "",
			HttpOnly: true,
			Secure:   true,
			Expires:  time.Unix(0, 0), // Expire the cookie immediately
		},
	)

	return c.NoContent(204)
}

// RefreshSession handles the session refresh request by validating the provided refresh token and issuing a new access token and refresh token if the refresh token is valid.
func (h *AuthHandler) RefreshSession(c echo.Context) error {
	refreshTokenCookie, err := c.Cookie("refresh_token")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("missing refresh token cookie: %v", err))
	}
	refreshToken := refreshTokenCookie.Value

	newAccessToken, newRefreshToken, err := h.AuthUsecase.RefreshSessionToken(c.Request().Context(), refreshToken)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("failed to refresh session: %v", err))
	}

	newCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Now().Add(15 * 24 * time.Hour),
		Path:     "/refresh",
		// could add SameSite attribute if needed
		// could add another sites for different environments (e.g., development vs production)
	}
	c.SetCookie(newCookie)

	return c.JSON(200, map[string]string{"access_token": newAccessToken})
}
