package auth

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/postgres"
)

type Tokens struct {
	Access  string
	Refresh string
}

type AuthService struct {
	logger *slog.Logger
	c      *test_medods.Config
	*postgres.PostgresConnection
}

func (a *AuthService) validateExpireTime() {

}

func (a *AuthService) validateToken() {

}

func (a *AuthService) generateJWT(userId string, expirePeriodMinutes int, secretKey string) (string, error) {
	accessClaims := jwt.MapClaims{
		"sub": userId,
		"exp": time.Now().Add(time.Minute * time.Duration(expirePeriodMinutes)),
		"iat": time.Now(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	jwt, err := t.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return jwt, nil
}

// executed by /token{id}

func (a *AuthService) CreateTokens(ctx context.Context, userId string, userAgent string, userIp string) (*Tokens, error) {
	access, err := a.generateJWT(userId, a.c.Auth.AccessTokenExpirePeriodMinutes, a.c.Auth.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("Error occured during access token creating")
	}
	refresh, err := a.generateJWT(userId, a.c.Auth.AccessTokenExpirePeriodMinutes, a.c.Auth.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("Error occured during access refresh token creating")
	}

	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("Error occured during")
	}

	return &Tokens{Access: access, Refresh: refresh}, nil
}

// current user

func (a *AuthService) GetCurrentUserGUID(token)
