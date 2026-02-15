package http

import (
	"log/slog"
	"main/internal/config"
	handler "main/internal/delivery/http/auth_handler"
	metrics "main/internal/metrics"

	"github.com/labstack/echo/v4"
	middleware "github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

func MapRoutes(
	e *echo.Echo,
	authHandler *handler.AuthHandler,
	authUsecase AuthUsecase,
	logger *slog.Logger,
	rateLimiterConfig config.RateLimiterConfig,
	m *metrics.Metrics,
	client *redis.Client,
) {
	// Middlewares
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		Skipper:   func(c echo.Context) bool { return c.Path() == "/metrics" }, // Skip logging for /metrics endpoint
		LogURI:    true,
		LogMethod: true,
		LogStatus: true,
		LogError:  true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {

			if v.Error != nil && v.Error.Error() == "gRPC Client Error" {
				return nil // ingore gRPC client errors in HTTP logs, as they are handled separately in gRPC interceptors
			}

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

	//routes
	e.POST("/logout", authHandler.Logout, MetricsMiddleware(m))
	e.POST("/logout_all", authHandler.LogoutAll, AuthMiddleware(authUsecase), MetricsMiddleware(m))
	e.POST("/register", authHandler.Register, MetricsMiddleware(m))
	e.POST("/login", authHandler.Login, RateLimitMiddleware(client, &rateLimiterConfig), MetricsMiddleware(m))
	e.POST("/refresh", authHandler.RefreshSession, MetricsMiddleware(m))
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))

	logger.Info("HTTP routes mapped successfully")
}
