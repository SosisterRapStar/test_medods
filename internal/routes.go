package internal

import (
	"log/slog"
	"net/http"

	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/core"
)

// Not Implemented
func addRoutes(mux *http.ServeMux, logger *slog.Logger, config *test_medods.Config) {
	// Not Implemented
}

func accessEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		_ = authService.CreateTokens()
	}
}

func refreshTokensEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		_ = authService.UpdateTokens()
	}
}

func updateTokensEndpointRoute(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		_ = authService.CreateTokens()
	}
}

func getCurrentUserGUIDEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		_ = authService.GetCurrentUserGUID()
	}
}

func unauthorizeEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		_ = authService.UnauthorizeUser()
	}
}
