package core

type Auth interface {
	GetUserIdFromToken() error
	CreateTokens() error
	RefreshToken() error
	UpdateTokens() error
	GetCurrentUserGUID() error
	UnauthorizeUser() error
}
