package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/core"
	"github.com/sosisterrapstar/test_medods/internal/postgres"
	"golang.org/x/crypto/bcrypt"
)

const DEFAULT_INTERNAL_ERROR_STRING = "internal server error"

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

// We can logout user before his token got expired so we should check if a user was logout but still has active access token
func (a *AuthService) checkIfUserLoggedOut(ctx context.Context, userId string, issuedAt *jwt.NumericDate) (bool, error) {
	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		logger.Error("Error occured getting connection")
		return false, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	defer conn.Release()
	query := 
}

func (a *AuthService) AuthenticateUser(ctx context.Context, tokenString string) (string, error) {
	token, err := a.validateToken(tokenString, a.c.Auth.SecretKey)
	if err != nil {
		return "", err
	}
	claims := token.Claims
	userId, err := claims.GetSubject()
	if err != nil {
		a.logger.Error("Error occured during getting user Id from token")
		return "", &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		a.logger.Error("Error occured during getting issuedAt time from token")
		return "", &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	isLoggedOut, _ := a.checkIfUserLoggedOut(ctx, userId, issuedAt)
	if isLoggedOut {
		return "", &core.ForbiddenError{Err: errors.New("access to this recource is denied")}
	}
	return userId, nil
}

func (a *AuthService) validateToken(tokenString string, key string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			a.logger.Warn(fmt.Sprintf("Strange activity token can be changed on client side %s"))
			return nil, errors.New("unexpected sign method token invalid")
		}
		return []byte(key), nil
	})
	if err != nil {
		return nil, &core.AuthorizationError{Err: errors.New("can not authorize user")}
	}
	return token, err
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

func (a *AuthService) getHashFromSign(jwtSign string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(jwtSign), bcrypt.MinCost)
	return string(bytes), err
}

// executed by /token{id}

func (a *AuthService) saveRefreshToken(ctx context.Context, refresh string, userId string, userAgent string, userIp string) error {
	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		a.logger.Error("Error occured during db connection acquiring token creating")
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	defer conn.Release()

	tx, err := startTransaction(ctx, conn, pgx.ReadCommitted)
	if err != nil {
		a.logger.Error("Error occured during starting the transaction in db")
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	defer tx.Rollback(ctx)

	userIdInUUID, err := uuid.Parse(userId)
	if err != nil {
		a.logger.Error(fmt.Sprintf("Error occured during parsing user id %s id to uuid", userId))
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	signHash, err := a.getHashFromSign(refresh)
	if err != nil {
		a.logger.Error("Error occured during bcrypt hashing of refresh JWT sign")
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	token_info := core.TokenInfo{
		UserId:     userIdInUUID,
		Id:         uuid.New(),
		SignHash:   signHash,
		IssuedToUA: userAgent,
		IssuedToIP: userIp,
		IsRevoked:  false,
	}
	query := "INSERT INTO auth.tokens (token_id, user_id, sign_hash, issued_to_ua, issued_to_ip, is_revoked) VALUES ($1, $2, $3, $4, $5, $6)"
	if _, err = tx.Exec(ctx, query, token_info.Id, token_info.UserId, token_info.SignHash, token_info.IssuedToUA, token_info.IssuedToIP, token_info.IsRevoked); err != nil {
		a.logger.Error(fmt.Sprintf("Failed to execute query %s", query))
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	if err := tx.Commit(ctx); err != nil {
		a.logger.Error("Failed to commit transaction", "error", err)
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}


	return nil

}

func (a *AuthService) CreateTokens(ctx context.Context, userId string, userAgent string, userIp string) (*Tokens, error) {
	access, err := a.generateJWT(userId, a.c.Auth.AccessTokenExpirePeriodMinutes, a.c.Auth.SecretKey)
	if err != nil {
		a.logger.Error("Error occured during access token creating")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	refresh, err := a.generateJWT(userId, a.c.Auth.AccessTokenExpirePeriodMinutes, a.c.Auth.SecretKey)
	if err != nil {
		a.logger.Error("Error occured during refresh token creating")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	if err := a.saveRefreshToken(ctx, refresh, userId, userAgent, userIp); err != nil {
		return nil, err
	}
	return &Tokens{Access: access, Refresh: refresh}, nil
}

// current user

func (a *AuthService) RevokeAllUserTokens(ctx context.Context, userId string) {
	// not Implmented
	return
}

func (a *AuthService) GetCurrentUserGUID(token string) {
	// not Implmented
	return
}
