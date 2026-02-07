package grp

import (
	"context"
	"log/slog"
	authv1 "main/pkg/proto/gen/auth/v1"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type RPCAuthHandler struct {
	authv1.UnimplementedAuthServiceServer
	logger      *slog.Logger
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

func NewAuthHandler(logger *slog.Logger, authUsecase AuthUsecase) *RPCAuthHandler {
	return &RPCAuthHandler{
		logger:      logger,
		AuthUsecase: authUsecase,
	}

}

// RegisterUser registers a new user and returns the user ID.
func (h *RPCAuthHandler) RegisterUser(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	userID, err := h.AuthUsecase.RegisterUser(ctx, req.Username, req.Email, req.Password)
	if err != nil {
		h.logger.Error("Failed to register user", "error", err)
		return nil, err
	}
	return &authv1.RegisterResponse{
		UserId: userID.String()}, nil

}

// LoginUser authenticates the user and returns an access token if successful.
func (h *RPCAuthHandler) LoginUser(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if req.GetLogin() == "" || req.GetPassword() == "" {
		h.logger.Error("Login or password is empty")
		return nil, status.Error(codes.InvalidArgument, "login or password is empty")
	}
	userAgent := getUserAgent(ctx)
	clientIP := getClientIP(ctx)
	token, err := h.AuthUsecase.LoginUser(ctx, req.GetLogin(), req.GetPassword(), userAgent, clientIP)
	if err != nil {
		h.logger.Error("Failed to login user", "error", err)
		return nil, err
	}
	return &authv1.LoginResponse{
		Token: token,
	}, nil

}

// LogoutSession logs out the user from a specific session by deleting that session from the database.
func (h *RPCAuthHandler) LogoutSession(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	err := h.AuthUsecase.LogoutSession(ctx, req.GetUserId(), req.GetSessionId())
	if err != nil {
		h.logger.Error("Failed to logout session", "error", err)
		return nil, err
	}
	return &authv1.LogoutResponse{
		Success: true,
	}, nil
}

// LogoutAllSessions logs out the user from all sessions by deleting all sessions associated with the user from the database.
func (h *RPCAuthHandler) LogoutAllSessions(ctx context.Context, req *authv1.LogoutAllRequest) (*authv1.LogoutAllResponse, error) {
	err := h.AuthUsecase.LogoutAllSessions(ctx, req.GetUserId())
	if err != nil {
		h.logger.Error("Failed to logout all sessions", "error", err)
		return nil, err
	}
	return &authv1.LogoutAllResponse{
		Success: true,
	}, nil
}

// getClientIP extracts the client IP address from gRPC metadata or peer info.
func getClientIP(ctx context.Context) string {
	// 1. First, try to get the IP from gRPC metadata headers
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		// Standard header for client IP
		if xff := md.Get("x-forwarded-for"); len(xff) > 0 {
			// The X-Forwarded-For header can contain multiple IPs, the first one is the client's IP
			ips := strings.Split(xff[0], ",")
			return strings.TrimSpace(ips[0])
		}

		// Common alternative header
		if xrip := md.Get("x-real-ip"); len(xrip) > 0 {
			return xrip[0]
		}
	}

	// 2. Fallback to peer info from context
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}

	return "unknown"
}

// getUserAgent extracts the User-Agent from gRPC metadata.
func getUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "unknown"
	}

	//gRPC initially sets user-agent in "user-agent" metadata field
	if ua := md.Get("user-agent"); len(ua) > 0 {
		return ua[0]
	}

	// Some proxies forward the original UA in x-user-agent
	if ua := md.Get("grpc-gateway-user-agent"); len(ua) > 0 {
		return ua[0]
	}

	return "unknown"
}
