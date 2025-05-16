package main

import (
	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/auth"
	"github.com/sosisterrapstar/test_medods/internal/postgres"
)

// Abstract
func main() {
	config := test_medods.MustLoad()
	logger := test_medods.SetupLogger()
	psConn := postgres.PostgresConnection{}
	psConn.Open(logger, config)
	authService := &auth.AuthService{
		logger,
		config,
		&psConn,
	}
}
