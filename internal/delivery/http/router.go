package http

import (
	"log/slog"
	handler "main/internal/delivery/http/auth_handler"

	"github.com/labstack/echo/v4"
	middleware "github.com/labstack/echo/v4/middleware"
)

func MapRoutes(e *echo.Echo, authHandler *handler.AuthHandler, authUsecase AuthUsecase, logger *slog.Logger) {
	// Middlewares
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		Skipper:   middleware.DefaultSkipper,
		LogURI:    true,
		LogMethod: true,
		LogStatus: true,
		LogError:  true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error != nil {
				logger.Error("HTTP request error",
					"method", v.Method,
					"uri", v.URI,
					"status", v.Status,
					"error", v.Error,
				)
				return nil
			}

			logger.Info("HTTP request",
				"method", v.Method,
				"uri", v.URI,
				"status", v.Status,
				"error", v.Error,
			)

			return nil
		},
	},
	))
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Auth routes
	e.POST("/logout", authHandler.Logout, AuthMiddleware(authUsecase))
	e.POST("/logout_all", authHandler.LogoutAll, AuthMiddleware(authUsecase))
	e.POST("/register", authHandler.Register)
	e.POST("/login", authHandler.Login)

	logger.Info("HTTP routes mapped successfully")
}
