package core

type Auth interface {
	GetUserIdFromToken() error
	CreateTokens() error
	RefreshToken() error
	UpdateTokens() error
	GetCurrentUserGUID() error
	UnauthorizeUser() error
}

// Service Layer Errors

type InternalError struct {
	Err error
}

type AuthorizationError struct {
	Err error
}

type RequestError struct {
	Err error
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
