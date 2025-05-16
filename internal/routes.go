package internal

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal/core"
)

type HTTPErrorMessage struct {
	status  int
	message string
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}

func validateError(err error) HTTPErrorMessage {

	switch {
	case errors.As(err, &core.AuthorizationError{}):
		return HTTPErrorMessage{status: http.StatusUnauthorized, message: err.Error()}
	case errors.Is(err, &core.ForbiddenError{}):
		return HTTPErrorMessage{status: http.StatusForbidden, message: err.Error()}
	case errors.As(err, &core.InternalError{}):
		return HTTPErrorMessage{status: http.StatusInternalServerError, message: err.Error()} // Исправлено на HTTPErrorMessage
	case errors.As(err, &core.RequestError{}):
		return HTTPErrorMessage{status: http.StatusBadRequest, message: err.Error()}
	default:
		return HTTPErrorMessage{status: http.StatusInternalServerError, message: "server internal error"}
	}
}

// Not Implemented
func addRoutes(mux *http.ServeMux, logger *slog.Logger, config *test_medods.Config) {
	// Not Implemented
}

// func accessEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
// 	return func(rw http.ResponseWriter, r *http.Request) {
// 		_ = authService.CreateTokens()
// 	}
// }

// func refreshTokensEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
// 	return func(rw http.ResponseWriter, r *http.Request) {
// 		_ = authService.UpdateTokens()
// 	}
// }

// func updateTokensEndpointRoute(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
// 	return func(rw http.ResponseWriter, r *http.Request) {
// 		_ = authService.CreateTokens()
// 	}
// }

func getCurrentUserGUIDEndpoint(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user, ok := userFromContext(ctx)
		if !ok {
			logger.Error("Something went wrong with auth middleware")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "server internal error"})
			return
		}
		uuid := user.Id.String()
		writeJSON(w, http.StatusOK, map[string]string{"user_id": uuid})
		return
	}
}

// func unauthorizeEndpoint(logger *slog.Logger, authService core.Auth) http.HandlerFunc {
// 	return func(rw http.ResponseWriter, r *http.Request) {
// 		_ = authService.UnauthorizeUser()
// 	}
// }
