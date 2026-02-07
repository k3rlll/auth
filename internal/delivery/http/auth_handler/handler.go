package authHandler

import (
	"context"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	AuthUsecase AuthUsecase
}

type AuthUsecase interface {

	//RegisterUser registers a new user and returns the user ID as a string.
	RegisterUser(ctx context.Context, username, email, password string) (userID uuid.UUID, err error)

	//LoginUser authenticates a user and returns an access token.
	LoginUser(ctx context.Context, login, password, userAgent string, ip string) (accessToken string, err error)

	//LogoutSession logs out a user from a specific session.
	LogoutSession(ctx context.Context, userID string, sessionID string) error

	//LogoutAllSessions logs out a user from all sessions.
	LogoutAllSessions(ctx context.Context, userID string) error
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
		return err
	}
	userID, err := h.AuthUsecase.RegisterUser(c.Request().Context(), req.Username, req.Email, req.Password)
	if err != nil {
		return err
	}
	return c.JSON(201, map[string]string{"user_id": userID.String()})
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	accessToken, err := h.AuthUsecase.LoginUser(c.Request().Context(), req.Login, req.Password, c.Request().UserAgent(), c.RealIP())
	if err != nil {
		return err
	}
	return c.JSON(200, map[string]string{"access_token": accessToken})

}

func (h *AuthHandler) Logout(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	err := h.AuthUsecase.LogoutSession(c.Request().Context(), req.UserID, req.SessionID)
	if err != nil {
		return err
	}
	return c.NoContent(204)
}

func (h *AuthHandler) LogoutAll(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	err := h.AuthUsecase.LogoutAllSessions(c.Request().Context(), req.UserID)
	if err != nil {
		return err
	}
	return c.NoContent(204)
}
