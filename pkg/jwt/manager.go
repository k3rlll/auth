package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTManager struct {
	secretKey      string
	accessTokenTTL int
}

func NewJWTManager(secretKey string, tokenTTL int) *JWTManager {
	return &JWTManager{
		secretKey:      secretKey,
		accessTokenTTL: tokenTTL,
	}
}

// NewAccessToken generates a new JWT access token for the given user ID.
func (manager *JWTManager) NewAccessToken(userID uuid.UUID) (string, error) {
	jwtClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Duration(manager.accessTokenTTL) * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	})
	tokenString, err := jwtClaims.SignedString([]byte(manager.secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// VerifyAccessToken verifies the access token and returns the user ID if the token is valid.
func (manager *JWTManager) VerifyAccessToken(tokenString string) (userID uuid.UUID, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenMalformed
		}
		return []byte(manager.secretKey), nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	sub, err := token.Claims.GetSubject()
	if err != nil || sub == "" {
		return uuid.Nil, jwt.ErrTokenMalformed
	}

	uuid := uuid.MustParse(sub)

	return uuid, nil
}
