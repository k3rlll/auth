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
	RefreshSessionToken(ctx context.Context, refreshToken string, userID string) (newAccessToken string, newRefreshToken string, err error)
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
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request", err.Error())
	}
	userID, err := h.AuthUsecase.RegisterUser(c.Request().Context(), req.Username, req.Email, req.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to register user", err.Error())
	}
	return c.JSON(201, map[string]string{"user_id": userID.String()})
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request", err.Error())
	}
	userID, accessToken, refreshToken, err := h.AuthUsecase.LoginUser(
		c.Request().Context(),
		req.Login,
		req.Password,
		c.Request().UserAgent(),
		c.RealIP())
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid credentials", err.Error())
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

func (h *AuthHandler) Logout(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request", err.Error())
	}
	err := h.AuthUsecase.LogoutSession(c.Request().Context(), req.UserID, req.SessionID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to logout session", err.Error())
	}
	return c.NoContent(204)
}

func (h *AuthHandler) LogoutAll(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request", err.Error())
	}
	err := h.AuthUsecase.LogoutAllSessions(c.Request().Context(), req.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to logout all sessions", err.Error())
	}
	return c.NoContent(204)
}

func (h *AuthHandler) RefreshSession(c echo.Context) error {
	refreshTokenCookie, err := c.Cookie("refresh_token")
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "refresh_token cookie is required", err.Error())
	}
	refreshToken := refreshTokenCookie.Value

	// In a real application, you would also need to extract the user ID from the access token or session
	// For this example, we'll assume the user ID is passed as a query parameter (not recommended for production)
	userID := c.Get("user_id")
	if userID == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "user_id is required", fmt.Errorf("user_id not found in context"))
	}
	newAccessToken, newRefreshToken, err := h.AuthUsecase.RefreshSessionToken(c.Request().Context(), refreshToken, userID.(string))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to refresh session", err.Error())
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
