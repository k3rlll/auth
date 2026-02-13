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
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	cfg := config.LoadConfig()
	logger := setupLogger(cfg.Env)
	logger.Info("Application started", "env", cfg.Env)

	//database connection setup
	dsn := cfg.PostgresConfig.DSN()
	pool, err := psql.NewPostgresConnection(dsn)
	if err != nil {
		logger.Error("Failed to connect to the database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	logger.Info("Connected to the database successfully")

	//Redis client setup
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisConfig.Addr,
		Password: cfg.RedisConfig.Password,
		DB:       cfg.RedisConfig.DB,
	})
	defer redisClient.Close()

	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		logger.Error("Failed to connect to Redis", "error", err)
		os.Exit(1)
	}
	logger.Info("Connected to Redis successfully")

	//  Init Core Logic
	jwtManager := jwt.NewJWTManager(cfg.JWTConfig.Secret, cfg.JWTConfig.ExpirationMinutes)
	authRepository := authRepo.NewAuthRepo(pool)
	authUsecase := authUs.NewAuthUsecase(authRepository, jwtManager)

	// Init Handlers
	httpHandler := httpAuthHandler.NewAuthHandler(authUsecase)
	grpcHandler := grpcAuthHandler.NewAuthHandler(logger, authUsecase)

	//  HTTP Server Setup (Echo)
	e := echo.New()
	e.HTTPErrorHandler = errHandler.HandleError
	routes.MapRoutes(e, httpHandler, authUsecase, logger, cfg.RateLimiterConfig, redisClient)

	// http.Server configuration with timeouts for better resource management and security
	httpAddr := net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port))
	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      e,
		ReadTimeout:  cfg.Server.Timeout,
		WriteTimeout: cfg.Server.Timeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// gRPC Server Setup
	grpcAddr := net.JoinHostPort(cfg.GrpcServer.Host, strconv.Itoa(cfg.GrpcServer.Port))
	//
	//
	//setup gRPC server with interceptors
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptor.RecoveryInterceptor(logger),
			interceptor.LoggingInterceptor(logger),
			interceptor.AuthInterceptor(jwtManager),
		))

	pb.RegisterAuthServiceServer(grpcServer, grpcHandler)
	// reflection for gRPC debugging tools (Postman/BloomRPC) - only in non-production environments
	if cfg.Env != "production" {
		reflection.Register(grpcServer)
	}

	//  Graceful Shutdown Setup
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	g, gCtx := errgroup.WithContext(ctx)

	//setup gRPC server in separate goroutine
	g.Go(func() error {
		lis, err := net.Listen("tcp", grpcAddr)
		if err != nil {
			return errors.New("failed to listen gRPC: " + err.Error())
		}
		logger.Info("gRPC server started", slog.String("addr", grpcAddr))

		if err := grpcServer.Serve(lis); err != nil {
			return errors.New("gRPC server failed: " + err.Error())
		}
		return nil
	})

	//setup HTTP server in separate goroutine
	g.Go(func() error {
		logger.Info("HTTP server started", slog.String("addr", httpAddr))
		if err := e.StartServer(httpServer); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return errors.New("HTTP server failed: " + err.Error())
		}
		return nil
	})

	// --- Graceful Shutdown ---
	g.Go(func() error {
		<-gCtx.Done()
		logger.Info("Shutting down servers...")

		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			if err := httpServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("HTTP shutdown error", slog.String("err", err.Error()))
			}
		}()

		go func() {
			defer wg.Done()
			grpcServer.GracefulStop()
		}()

		doneCh := make(chan struct{})
		go func() {
			wg.Wait()
			close(doneCh)
		}()

		select {
		case <-doneCh:
			logger.Info("Servers stopped gracefully")
		case <-shutdownCtx.Done():
			logger.Warn("Shutdown timeout exceeded, forcing gRPC stop")
			grpcServer.Stop()
		}

		return nil
	})

	//wait for all goroutines to finish
	if err := g.Wait(); err != nil {
		logger.Error("Application terminated with error", slog.Any("err", err))
		os.Exit(1)
	}
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case "production":
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	case "development", "local":
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	default:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return log
}
