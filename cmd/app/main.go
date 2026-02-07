package main

import (
	"context"
	"errors"
	"log/slog"
	"main/internal/config"
	grpcAuthHandler "main/internal/delivery/grpc/auth"
	"main/internal/delivery/grpc/interceptor"
	routes "main/internal/delivery/http"
	httpAuthHandler "main/internal/delivery/http/auth_handler"
	psql "main/internal/storage/postgres"
	authRepo "main/internal/storage/postgres/auth"
	authUs "main/internal/usecase/auth"
	errHandler "main/pkg/error_handler"
	"main/pkg/jwt"
	pb "main/pkg/proto/gen/auth/v1"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

func main() {
	config := config.LoadConfig()
	logger := setupLogger(config.Env)
	logger.Info("Application started", "env", config.Env)

	// Initialize Postgres connection
	DSN := config.PostgresConfig.DSN()
	pool, err := psql.NewPostgresConnection(DSN)
	if err != nil {
		logger.Error("Failed to connect to the database", "error", err)
		return
	}
	defer pool.Close()
	logger.Info("Connected to the database successfully")

	jwtManager := jwt.NewJWTManager(config.JWTConfig.Secret, config.JWTConfig.ExpirationMinutes)

	// Initialize Echo
	e := echo.New()
	e.HTTPErrorHandler = errHandler.HandleError

	// Initialize repositories
	authRepo := authRepo.NewAuthRepo(pool)

	// Initialize use cases
	authUsecase := authUs.NewAuthUsecase(authRepo, jwtManager)

	// Initialize handlers and map routes
	httpAuthHandler := httpAuthHandler.NewAuthHandler(authUsecase)
	routes.MapRoutes(e, httpAuthHandler, authUsecase, logger)
	grpcAuthHandler := grpcAuthHandler.NewAuthHandler(logger, authUsecase)

	serverParams := &http.Server{
		Addr:         net.JoinHostPort(config.Server.Host, strconv.Itoa(config.Server.Port)),
		Handler:      e,
		ReadTimeout:  config.Server.Timeout,
		WriteTimeout: config.Server.Timeout,
		IdleTimeout:  config.Server.IdleTimeout,
	}
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(interceptor.AuthInterceptor(jwtManager)),
	)

	pb.RegisterAuthServiceServer(grpcServer, grpcAuthHandler)

	// Start servers in separate goroutines and handle graceful shutdown
	// The application will run both the HTTP and gRPC servers concurrently.
	// It listens for interrupt signals (like Ctrl+C) to initiate a graceful shutdown process,
	// allowing ongoing requests to complete before the servers are stopped.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		logger.Info("gRPC server is starting on port", slog.String("addr", net.JoinHostPort(config.GrpcServer.Host, strconv.Itoa(config.GrpcServer.Port))))
		lis, err := net.Listen("tcp", net.JoinHostPort(config.GrpcServer.Host, strconv.Itoa(config.GrpcServer.Port)))
		if err != nil {
			return err
		}
		logger.Info("gRPC server is starting", slog.String("addr", lis.Addr().String()))
		if err := grpcServer.Serve(lis); err != nil {
			return err
		}
		return nil
	})
	g.Go(func() error {
		logger.Info("Starting HTTP server on port", slog.String("addr", net.JoinHostPort(config.Server.Host, strconv.Itoa(config.Server.Port))))
		return e.Start(net.JoinHostPort(config.Server.Host, strconv.Itoa(config.Server.Port)))
	})

	// Graceful shutdown
	// Wait for interrupt signal to gracefully shutdown the servers with a timeout of 5 seconds.
	// When an interrupt signal is received, the application will attempt to gracefully shut down both the HTTP and gRPC servers.
	g.Go(func() error {
		<-gCtx.Done()
		logger.Info("shutting down servers...")

		shutDownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if err := serverParams.Shutdown(shutDownCtx); err != nil {
				logger.Error("HTTP server shutdown failed", slog.String("error", err.Error()))
			}
		}()

		go func() {
			defer wg.Done()
			grpcServer.GracefulStop()
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			logger.Info("All servers stopped gracefully")
		case <-shutDownCtx.Done():
			logger.Warn("Shutdown timeout exceeded, forcing stop")
			grpcServer.Stop()
		}

		return nil
	})

	// Wait for all goroutines to finish and check for errors
	if err := g.Wait(); err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Error("Application stopped with error", slog.Any("err", err))
			os.Exit(1)
		}
	}
}

// setupLogger configures the logger based on the environment (production, development, local).
func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case "production":
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	case "development", "local":
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	default:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return log
}
