package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/core"
	"github.com/sosisterrapstar/test_medods/internal/postgres"
)

func startTransaction(ctx context.Context, conn *pgxpool.Conn, isolation pgx.TxIsoLevel) (pgx.Tx, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
	if err != nil {
		return nil, err
	}
	return tx, nil
}

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
		a.logger.Error("Error occured during access token creating")
		return nil, &core.InternalError{Err: errors.New("Server error")}
	}
	refresh, err := a.generateJWT(userId, a.c.Auth.AccessTokenExpirePeriodMinutes, a.c.Auth.SecretKey)
	if err != nil {
		a.logger.Error("Error occured during refresh token creating")
		return nil, &core.InternalError{Err: errors.New("Server error")}
	}

	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		a.logger.Error("Error occured during db connection acquiring token creating")
		return nil, &core.InternalError{Err: errors.New("Server error")}
	}

	defer conn.Release()

	tx, err := startTransaction(ctx, conn, pgx.ReadCommitted)
	if err != nil {
		a.logger.Error("Error occured during starting the transaction in db")
		return nil, &core.InternalError{Err: errors.New("Server error")}
	}
	defer tx.Rollback(ctx)

	tx.Exec(ctx, "")
	return &Tokens{Access: access, Refresh: refresh}, nil
}

// current user

func (a *AuthService) GetCurrentUserGUID(token)
