package http

import (
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type AuthUsecase interface {
	// VerifyUser verifies the access token and returns the user ID.
	VerifyUser(token string) (userID uuid.UUID, err error)
}

func AuthMiddleware(authUsecase AuthUsecase) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			header := c.Request().Header.Get("authorization")
			if header == "" || !strings.HasPrefix(header, "Bearer ") {
				return echo.NewHTTPError(401, "Unauthorized")
			}

			accessToken := strings.TrimPrefix(header, "Bearer ")

			userID, err := authUsecase.VerifyUser(accessToken)
			if err != nil {
				return echo.NewHTTPError(401, "Unauthorized")
			}
			if userID == uuid.Nil {
				return echo.NewHTTPError(401, "Unauthorized")
			}

			c.Set("userID", userID)
			return next(c)
		}
	}
}
