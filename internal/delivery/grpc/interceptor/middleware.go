package interceptor

import (
	"context"
	ctxUtil "main/pkg/utils/context"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var publicMethods = map[string]struct{}{
	"/auth.v1.AuthService/Register": {},
	"/auth.v1.AuthService/Login":    {},
}

type JWTManager interface {
	VerifyAccessToken(tokenString string) (userID uuid.UUID, err error)
}

// AuthInterceptor is a gRPC middleware that intercepts incoming requests to perform authentication.
func AuthInterceptor(jwtManager JWTManager) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if _, ok := publicMethods[info.FullMethod]; ok {
			// Public method, proceed without authentication
			return handler(ctx, req)
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}

		values := md["authorization"]
		if len(values) == 0 {
			return nil, status.Errorf(codes.Unauthenticated, "missing authorization token")
		}

		accessToken := strings.TrimPrefix(values[0], "Bearer ")

		userID, err := jwtManager.VerifyAccessToken(accessToken)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		newCtx := ctxUtil.NewContext(ctx, userID.String())

		return handler(newCtx, req)
	}
}
