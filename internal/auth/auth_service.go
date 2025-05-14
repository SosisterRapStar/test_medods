package auth

import (
	"log/slog"

	"github.com/sosisterrapstar/test_medods/internal/postgres"
)

type AuthService struct {
	logger *slog.Logger
	*postgres.PostgresConnection
}
