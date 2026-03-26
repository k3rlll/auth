package mocks

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"

	"main/domain/entity"
	"main/internal/metrics"
	uc "main/internal/usecase/auth"
)

// setupTest initializes the test environment for AuthUsecase tests,
// creating mock instances of AuthRepo and JWTManager.
func setupTest(t *testing.T) (*uc.AuthUsecase, *MockAuthRepo, *MockJWTManager) {
	ctrl := gomock.NewController(t)

	repo := NewMockAuthRepo(ctrl)
	jwtMgr := NewMockJWTManager(ctrl)
	testMetrics := &metrics.Metrics{
		LoginAttempts: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "test_login_attempts",
				Help: "Test counter",
			},
			[]string{"status"}, // Тут указываешь лейблы, которые используются в коде ("status")
		),
	}

	uc := uc.NewAuthUsecase(repo, jwtMgr, testMetrics)
	return uc, repo, jwtMgr
}

func TestAuthUsecase_RegisterUser(t *testing.T) {
	uc, repo, _ := setupTest(t)

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		username := "testuser"
		email := "test@example.com"
		password := "StrongPass1!"

		repo.EXPECT().
			CreateUser(ctx, gomock.Any(), email, username, gomock.Any()).
			Return(uuid.New(), nil).
			Times(1)

		userID, err := uc.RegisterUser(ctx, username, email, password)

		assert.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, userID)
	})

	t.Run("invalid username", func(t *testing.T) {
		userID, err := uc.RegisterUser(ctx, "ab", "test@example.com", "StrongPass1!")
		assert.Error(t, err)
		assert.Equal(t, "username must be between 3 and 30 characters", err.Error())
		assert.Equal(t, uuid.Nil, userID)
	})

	t.Run("invalid email", func(t *testing.T) {
		_, err := uc.RegisterUser(ctx, "testuser", "invalid-email", "StrongPass1!")
		assert.Error(t, err)
		assert.Equal(t, "invalid email format", err.Error())
	})

	t.Run("weak password", func(t *testing.T) {
		userID, err := uc.RegisterUser(ctx, "testuser", "test@example.com", "weak")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "password must be at least 8 characters long")
		assert.Equal(t, uuid.Nil, userID)
	})
}

func TestAuthUsecase_LoginUser(t *testing.T) {
	uc, repo, jwtMgr := setupTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		login := "testuser"
		password := "StrongPass1!"
		hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		expectedUserID := uuid.New()
		ip := "192.168.1.1"
		userAgent := "Mozilla/5.0"

		repo.EXPECT().GetUserByLogin(ctx, login).Return(expectedUserID, string(hash), nil).Times(1)
		jwtMgr.EXPECT().NewAccessToken(expectedUserID).Return("access_token", nil).Times(1)

		repo.EXPECT().StoreSession(ctx, expectedUserID, gomock.Any()).Return(nil).Times(1)

		userID, accessToken, refreshToken, err := uc.LoginUser(ctx, login, password, userAgent, ip)

		assert.NoError(t, err)
		assert.Equal(t, expectedUserID, userID)
		assert.Equal(t, "access_token", accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("invalid credentials - user not found", func(t *testing.T) {
		login := "wronguser"
		password := "StrongPass1!"

		repo.EXPECT().GetUserByLogin(ctx, login).Return(uuid.Nil, "", errors.New("user not found")).Times(1)

		userID, accessToken, refreshToken, err := uc.LoginUser(ctx, login, password, "", "127.0.0.1")

		assert.Error(t, err)
		assert.Equal(t, "user not found", err.Error())
		assert.Equal(t, uuid.Nil, userID)
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})

	t.Run("invalid credentials - wrong password", func(t *testing.T) {
		login := "testuser"
		wrongPassword := "WrongPass1!"
		hash, _ := bcrypt.GenerateFromPassword([]byte("StrongPass1!"), bcrypt.DefaultCost)
		expectedUserID := uuid.New()

		repo.EXPECT().GetUserByLogin(ctx, login).Return(expectedUserID, string(hash), nil).Times(1)

		userID, _, _, err := uc.LoginUser(ctx, login, wrongPassword, "", "127.0.0.1")

		assert.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())
		assert.Equal(t, uuid.Nil, userID)
	})
}

func TestAuthUsecase_RefreshSessionToken(t *testing.T) {
	uc, repo, jwtMgr := setupTest(t)
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		oldRefreshToken := uuid.New()
		userID := uuid.New()

		session := entity.Session{
			ID:           uuid.New(),
			UserID:       userID,
			RefreshToken: oldRefreshToken,
			CreatedAt:    time.Now().Add(-1 * time.Hour),
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}

		repo.EXPECT().GetSessionByRefreshToken(ctx, oldRefreshToken).Return(session, nil).Times(1)
		repo.EXPECT().RefreshSession(ctx, gomock.Any()).Return(nil).Times(1)
		jwtMgr.EXPECT().NewAccessToken(userID).Return("new_access_token", nil).Times(1)

		newAccess, newRefresh, err := uc.RefreshSessionToken(ctx, oldRefreshToken.String())

		assert.NoError(t, err)
		assert.Equal(t, "new_access_token", newAccess)
		assert.NotEmpty(t, newRefresh)
		assert.NotEqual(t, oldRefreshToken.String(), newRefresh)
	})

	t.Run("session expired", func(t *testing.T) {
		oldRefreshToken := uuid.New()
		userID := uuid.New()

		session := entity.Session{
			ID:           uuid.New(),
			UserID:       userID,
			RefreshToken: oldRefreshToken,
			CreatedAt:    time.Now().Add(-2 * time.Hour),
			ExpiresAt:    time.Now().Add(-1 * time.Hour),
		}

		repo.EXPECT().GetSessionByRefreshToken(ctx, oldRefreshToken).Return(session, nil).Times(1)
		repo.EXPECT().DeleteSession(ctx, userID, session.ID).Return(nil).Times(1)

		newAccess, newRefresh, err := uc.RefreshSessionToken(ctx, oldRefreshToken.String())

		assert.Error(t, err)
		assert.Equal(t, "session has expired", err.Error())
		assert.Empty(t, newAccess)
		assert.Empty(t, newRefresh)
	})
}

func TestAuthUsecase_VerifyUser(t *testing.T) {
	uc, repo, jwtMgr := setupTest(t)

	t.Run("success", func(t *testing.T) {
		token := "valid_token"
		expectedUserID := uuid.New()

		jwtMgr.EXPECT().VerifyAccessToken(token).Return(expectedUserID, nil).Times(1)
		repo.EXPECT().UserIsBlocked(expectedUserID).Return(false, nil).Times(1)

		userID, err := uc.VerifyUser(token)

		assert.NoError(t, err)
		assert.Equal(t, expectedUserID, userID)
	})

	t.Run("user is blocked", func(t *testing.T) {
		token := "valid_token"
		expectedUserID := uuid.New()

		jwtMgr.EXPECT().VerifyAccessToken(token).Return(expectedUserID, nil).Times(1)
		repo.EXPECT().UserIsBlocked(expectedUserID).Return(true, nil).Times(1)

		userID, err := uc.VerifyUser(token)

		assert.Error(t, err)
		assert.Equal(t, "user is blocked", err.Error())
		assert.Equal(t, uuid.Nil, userID)
	})
}
