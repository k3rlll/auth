package http

import (
	"context"
	"main/internal/config"
	metrics "main/internal/metrics"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
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

func RateLimitMiddleware(client *redis.Client, cfg *config.RateLimiterConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			// Get the client's IP address
			ip := c.RealIP()
			key := "rate_limit:" + ip
			ctx := context.Background()

			// Increment the request count for the IP address
			count, err := client.Incr(ctx, key).Result()
			if err != nil {
				return echo.NewHTTPError(500, "Internal Server Error")
			}

			// Set the expiration for the key if it's the first request
			if count == 1 {
				err := client.Expire(ctx, key, cfg.Window).Err()
				if err != nil {
					return echo.NewHTTPError(500, "Internal Server Error")
				}
			}

			// Check if the request count exceeds the limit
			if count > int64(cfg.Limit) {
				return echo.NewHTTPError(429, "Too Many Requests")
			}

			//Adding headers with rate limit info for frontend to use
			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(cfg.Limit))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(cfg.Limit-int(count)))
			return next(c)
		}

	}
}

func MetricsMiddleware(m *metrics.Metrics) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			startTime := time.Now()
			err := next(c)
			duration := time.Since(startTime).Seconds()

			path := c.Path()
			method := c.Request().Method
			status := strconv.Itoa(c.Response().Status)

			m.RequestDuration.WithLabelValues(method, path, status).Observe(duration)

			return err
		}
	}
}
