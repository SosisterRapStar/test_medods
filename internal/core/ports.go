package core

import "context"

type Auth interface {
	CreateTokens(ctx context.Context, userId string, userAgent string, userIp string) (*Tokens, error)
	RefreshTokens(ctx context.Context, refreshTokenString string, userAgent string, ip string) (*Tokens, error)
	AuthenticateUser(ctx context.Context, tokenString string) (*User, error)
	LogOutUser(ctx context.Context, user *User) error
}

// Service Layer Errors

type ForbiddenError struct {
	Err error
}

type InternalError struct {
	Err error
}

type AuthorizationError struct {
	Err error
}

type RequestError struct {
	Err error
}

func (e *ForbiddenError) Error() string {
	return e.Err.Error()
}

func (e *RequestError) Error() string {
	return e.Err.Error()
}

func (e *AuthorizationError) Error() string {
	return e.Err.Error()
}

func (e *InternalError) Error() string {
	return e.Err.Error()
}
