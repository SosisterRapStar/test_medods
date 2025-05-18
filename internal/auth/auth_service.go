package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/core"
	"github.com/sosisterrapstar/test_medods/internal/postgres"
	"github.com/sosisterrapstar/test_medods/internal/webhook"
	"golang.org/x/crypto/bcrypt"
)

const DEFAULT_INTERNAL_ERROR_STRING = "internal server error"
const DEFAULT_FORBIDDEN_ERROR_STRING = "resource forbidden"

func startTransaction(ctx context.Context, conn *pgxpool.Conn, isolation pgx.TxIsoLevel) (pgx.Tx, error) {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: isolation})
	if err != nil {
		return nil, err
	}
	return tx, nil
}

type AuthService struct {
	logger *slog.Logger
	c      *test_medods.Config
	*postgres.PostgresConnection
	webhook *webhook.IpWebhook
}

func NewAuthService(logger *slog.Logger, c *test_medods.Config, pool *postgres.PostgresConnection, webhook *webhook.IpWebhook) *AuthService {
	return &AuthService{
		logger:             logger,
		c:                  c,
		PostgresConnection: pool,
		webhook:            webhook,
	}
}

func (a *AuthService) AuthenticateUser(ctx context.Context, tokenString string, refreshToken string) (*core.User, error) {
	token, err := a.validateToken(tokenString, a.c.Auth.SecretKey)
	if err != nil {
		return nil, err
	}
	var refreshTokenParsed *jwt.Token
	refreshTokenParsed, err = a.validateToken(refreshToken, a.c.Auth.SecretKey)
	if err != nil {
		return nil, err
	}

	claims := token.Claims
	userId, err := claims.GetSubject()
	if err != nil {
		a.logger.Error("Error occured during getting user Id from token")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	issuedAtToken, err := claims.GetIssuedAt()
	if err != nil {
		a.logger.Error("Error occured during getting issuedAt time from token")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	refreshClaims := refreshTokenParsed.Claims
	issuedAtRefresh, err := refreshClaims.GetIssuedAt()
	if err != nil {
		a.logger.Error("Error occured during getting issuedAt time from token")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	if !issuedAtToken.Time.Equal(issuedAtRefresh.Time) {
		a.logger.Error("Error occured user tried to use tokens from different pairs")
		return nil, &core.AuthorizationError{Err: errors.New("can not authorize user")}
	}

	user, err := a.getUserFromDb(ctx, userId)
	if err != nil {
		return nil, err
	}
	isLoggedOut, _ := a.checkIfUserLoggedOut(user.LastLogout, issuedAtToken)
	if isLoggedOut {
		return nil, &core.ForbiddenError{Err: errors.New(DEFAULT_FORBIDDEN_ERROR_STRING)}
	}
	return user, nil
}

func (a *AuthService) validateToken(tokenString string, key string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			a.logger.Warn("Strange activity token can be changed on client side")
			return nil, errors.New("unexpected sign method token invalid")
		}
		return []byte(key), nil
	})
	if err != nil {
		a.logger.Error("Error occured during token validating", "error", err.Error())
		return nil, &core.AuthorizationError{Err: errors.New("can not authorize user")}
	}
	return token, nil
}

// TODO: вынести все acquire в отдельнюу функцию
func (a *AuthService) getUserFromDb(ctx context.Context, userId string) (*core.User, error) {
	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		a.logger.Error("Error occured getting connection ")
		return nil, err
	}
	defer conn.Release()

	query := "SELECT u.user_id, u.name, u.created_at, u.updated_at, u.last_logout FROM auth.users u WHERE u.user_id = $1"
	var user core.User
	err = conn.QueryRow(ctx, query, userId).Scan(&user.Id, &user.Name, &user.CreatedAt, &user.UpdatedAt, &user.LastLogout)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			a.logger.Warn(fmt.Sprintf("User doesn't exists but trying to use token %s", userId))
			return nil, &core.ForbiddenError{Err: errors.New(DEFAULT_FORBIDDEN_ERROR_STRING)}
		}
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	return &user, nil

}

// We can logout user before his token got expired so we should check if a user was logout but still has active access token
func (a *AuthService) checkIfUserLoggedOut(lastLogout *time.Time, issuedAt *jwt.NumericDate) (bool, error) {
	if lastLogout == nil {
		return false, nil
	}

	return lastLogout.After(issuedAt.Time), nil
}

func (a *AuthService) CreateTokens(ctx context.Context, userId string, userAgent string, userIp string) (*core.Tokens, error) {
	iat := time.Now() // в данном случае служит еще и id для проверки, были ли токены выданы одной парой
	access, err := a.generateJWT(userId, a.c.Auth.AccessTokenExpirePeriodMinutes, a.c.Auth.SecretKey, iat)
	if err != nil {
		a.logger.Error("Error occured during access token creating")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	refresh, err := a.generateJWT(userId, a.c.Auth.RefreshTokenExpirePeriodMinutes, a.c.Auth.SecretKey, iat)
	if err != nil {
		a.logger.Error("Error occured during refresh token creating")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	sign := strings.Split(refresh, ".")[2]

	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		a.logger.Error("Error occured during db connection acquiring token creating")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	tx, err := startTransaction(ctx, conn, pgx.ReadCommitted)
	if err != nil {
		a.logger.Error("Error occured during starting the transaction in db")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	defer tx.Rollback(ctx)

	// ревок прошлого токена
	if err := a.revokeAllUserRefreshTokens(ctx, userId, tx); err != nil {
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	if err := a.saveRefreshToken(ctx, tx, sign, userId, userAgent, userIp); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		a.logger.Error("Failed to commit transaction", "error", err)
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	return &core.Tokens{Access: access, Refresh: refresh}, nil
}

func (a *AuthService) generateJWT(userId string, expirePeriodMinutes int, secretKey string, issuedAt time.Time) (string, error) {
	accessClaims := jwt.RegisteredClaims{
		Subject:   userId,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * time.Duration(expirePeriodMinutes))),
		IssuedAt:  jwt.NewNumericDate(issuedAt),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, accessClaims)
	jwt, err := t.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return jwt, nil
}

func (a *AuthService) saveRefreshToken(ctx context.Context, tx pgx.Tx, refresh string, userId string, userAgent string, userIp string) error {

	userIdInUUID, err := uuid.Parse(userId)
	if err != nil {
		a.logger.Error(fmt.Sprintf("Error occured during parsing user id %s id to uuid", userId))
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	signHash, err := a.getHashFromSign([]byte(refresh))
	if err != nil {
		a.logger.Error("Error occured during bcrypt hashing of refresh JWT sign", "error", err.Error())
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
	return nil
}

func (a *AuthService) getHashFromSign(jwtSign []byte) (string, error) {
	a.logger.Debug("Hashing sign", "token", base64.StdEncoding.EncodeToString(jwtSign))
	if len(jwtSign) > 70 {
		jwtSign = jwtSign[:70]
	}
	// a.logger.Debug("Hashed token", "token", base64.StdEncoding.EncodeToString(byteSign))
	bytes, err := bcrypt.GenerateFromPassword(jwtSign, bcrypt.MinCost)
	return string(bytes), err
}

// executed by /token{id}

// current user

func (a *AuthService) LogOutUser(ctx context.Context, user *core.User) error {
	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		a.logger.Error("Error occured getting the connection")
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	defer conn.Release()

	cur_time := time.Now()
	query := "UPDATE auth.users AS u SET last_logout = $1 WHERE u.user_id = $2"
	tx, err := startTransaction(ctx, conn, pgx.ReadCommitted)
	if err != nil {
		a.logger.Error("Error occured during starting the transaction in db")
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, query, cur_time, user.Id); err != nil {
		a.logger.Error(fmt.Sprintf("Failed to execute query %s", query))
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	if err := a.revokeAllUserRefreshTokens(ctx, user.Id.String(), tx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		a.logger.Error("Failed to commit transaction", "error", err)
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	return nil
}

func (a *AuthService) RefreshTokens(ctx context.Context, refreshTokenString string, userAgent string, ip string) (*core.Tokens, error) {
	token, err := a.validateToken(refreshTokenString, a.c.Auth.SecretKey)
	if err != nil {
		return nil, err
	}
	claims := token.Claims
	userId, err := claims.GetSubject()
	if err != nil {
		a.logger.Error("Error occured during getting user Id from token")
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	user, err := a.getUserFromDb(ctx, userId)
	if err != nil {
		return nil, err
	}
	var tokenInfos []core.TokenInfo

	conn, err := a.Pool.Acquire(ctx)
	if err != nil {
		a.logger.Error("Error occured getting connection ")
		return nil, err
	}
	defer conn.Release()

	// корявый способ при котором всегда приходится ходить в базу
	query := `
		SELECT t.sign_hash, t.is_revoked, t.issued_to_ua, t.issued_to_ip 
		FROM auth.tokens t
		WHERE t.user_id = $1 and t.is_revoked = false; 
	`

	rows, err := conn.Query(ctx, query, userId)
	if err != nil {
		a.logger.Error(fmt.Sprintf("Error occured during quering user tokens %s", err.Error()))
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	defer rows.Close()

	for rows.Next() {
		var ti core.TokenInfo
		err = rows.Scan(&ti.SignHash, &ti.IsRevoked, &ti.IssuedToUA, &ti.IssuedToIP)
		if err != nil {
			a.logger.Error(fmt.Sprintf("Error occured during scan token %s", err.Error()))
			return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
		}
		tokenInfos = append(tokenInfos, ti)
	}
	if rows.Err() != nil {
		a.logger.Error(fmt.Sprintf("Error occured during rows checking %v", rows.Err()))
		return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}

	if len(tokenInfos) > 1 {
		// если длина больше 1 это значит, что сейчас несколько активных токенов и это очень плохо, я не знаю возможна ли такая ситуация
		if err := a.LogOutUser(ctx, user); err != nil {
			return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
		}
		a.logger.Warn(fmt.Sprintf("Finded two active tokens for one user %s", user.Id))
		return nil, &core.ForbiddenError{Err: errors.New(DEFAULT_FORBIDDEN_ERROR_STRING)}
	}
	if len(tokenInfos) == 0 {
		// если токен валиден но при этом у пользователя нет активных токенов
		if err := a.LogOutUser(ctx, user); err != nil { // выкидыввание пользователя из аккаунта для получения новых токенов
			return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
		}
		a.logger.Debug("No tokens in storage")
		a.logger.Warn(fmt.Sprintf("It seems someone reuse already revoked token %s", user.Id))
		return nil, &core.ForbiddenError{Err: errors.New(DEFAULT_FORBIDDEN_ERROR_STRING)}
	}

	dbToken := tokenInfos[0]
	tokenSign := []byte(strings.Split(refreshTokenString, ".")[2])

	// bcrypt не может хэшировать больше 72
	// a.logger.Debug(base64.StdEncoding.EncodeToString(tokenSign))

	isValid, err := a.bcryptValidateSign(tokenSign, []byte(dbToken.SignHash))
	if err != nil {
		return nil, err
	}
	if !isValid {
		// если токен прошел валидацию, но при этом он не активен, то выкидываем пользователя
		if err := a.LogOutUser(ctx, user); err != nil { // выкидыввание пользователя из аккаунта для получения новых токенов через авторизацю
			return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
		}
		a.logger.Debug("Can not validate token")
		a.logger.Warn(fmt.Sprintf("It seems someone reuse already revoked token %s", user.Id))
		return nil, &core.ForbiddenError{Err: errors.New(DEFAULT_FORBIDDEN_ERROR_STRING)}
	}

	// не совпадает UA
	if userAgent != dbToken.IssuedToUA {
		a.logger.Warn(fmt.Sprintf("User %s changed UA", user.Id))
		if err := a.LogOutUser(ctx, user); err != nil { // выкидыввание пользователя из аккаунта для получения новых токенов через авторизацю
			return nil, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
		}
		return nil, &core.ForbiddenError{Err: errors.New(DEFAULT_FORBIDDEN_ERROR_STRING)}
	}

	if ip != dbToken.IssuedToIP {
		a.logger.Warn("IP address changed",
			"user_id", user.Id,
			"stored_ip", dbToken.IssuedToIP,
			"current_ip", ip)
		if a.webhook != nil {
			event := webhook.IpUpdateEvent{
				Timestamp: time.Now(),
				PrevIp:    dbToken.IssuedToIP,
				NewIp:     ip,
				UserId:    user.Id.String(),
			}
			if err := a.webhook.SendEvent(event); err != nil {
				a.logger.Error("Error occured during sending request to webhook check service")
			}
		}
	}

	tokens, err := a.CreateTokens(ctx, user.Id.String(), userAgent, ip)
	if err != nil {
		return nil, err
	}

	return tokens, err

}

func (a *AuthService) bcryptValidateSign(currentSign []byte, storedSign []byte) (bool, error) {
	a.logger.Debug("Validating sign hash", "sign", base64.StdEncoding.EncodeToString(currentSign))

	if len(currentSign) > 70 {
		currentSign = currentSign[:70]
	}

	err := bcrypt.CompareHashAndPassword(storedSign, currentSign)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	a.logger.Error("Internal error occured during sign hash comparing")
	return false, &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}

}

// в данном случае лишняя логика так как можно было бы отзывать только последний созданный токен, но вдруг в будущем у пользователя может быть несколько устройств и тогда нужно было бы отозвать все токены или token family
func (a *AuthService) revokeAllUserRefreshTokens(ctx context.Context, userId string, tx pgx.Tx) error {
	query := "UPDATE auth.tokens t SET is_revoked = true WHERE t.user_id = $1 AND t.is_revoked = false"
	_, err := tx.Exec(ctx, query, userId)
	if err != nil {
		a.logger.Error(fmt.Sprintf("Error occured during revoking tokens for user %s", userId))
		return &core.InternalError{Err: errors.New(DEFAULT_INTERNAL_ERROR_STRING)}
	}
	return nil

}
