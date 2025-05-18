package internal

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

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
	var (
		authErr *core.AuthorizationError
		forbErr *core.ForbiddenError
		intErr  *core.InternalError
		reqErr  *core.RequestError
	)

	switch {
	case errors.As(err, &authErr):
		return HTTPErrorMessage{http.StatusUnauthorized, err.Error()}
	case errors.As(err, &forbErr):
		return HTTPErrorMessage{http.StatusForbidden, err.Error()}
	case errors.As(err, &intErr):
		return HTTPErrorMessage{http.StatusInternalServerError, err.Error()}
	case errors.As(err, &reqErr):
		return HTTPErrorMessage{http.StatusBadRequest, err.Error()}
	default:
		return HTTPErrorMessage{http.StatusInternalServerError, "server internal error"}
	}
}

// Not Implemented
func addRoutes(mux *http.ServeMux, logger *slog.Logger, config *test_medods.Config, auth core.Auth) {
	mux.HandleFunc("GET /api/v1/auth/access/{id}", accessEndpoint(logger, auth, config))
	mux.HandleFunc("GET /api/v1/auth/refresh", refreshEndpoint(logger, auth, config))
	mux.HandleFunc("GET /api/v1/auth/unauthorized", authenticationMiddleware(unauthorizeUserEndpoint(logger, auth, config), auth, logger))
	mux.HandleFunc("GET /api/v1/auth/me", authenticationMiddleware(getCurrentUserGUIDEndpoint(logger), auth, logger))

}

func accessEndpoint(logger *slog.Logger, auth core.Auth, c *test_medods.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokens *core.Tokens
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		id := r.PathValue("id")

		userAgent := r.Header.Get("User-Agent")
		// сервис не расчитан на работу за балансировщиком, поэтому не проверяет ip в X-Forwarded-For
		ipAddr := r.RemoteAddr

		tokens, err := auth.CreateTokens(ctx, id, userAgent, ipAddr)
		if err != nil {
			httpErr := validateError(err)
			writeJSON(w, httpErr.status, map[string]string{"message": httpErr.message})
			return
		}

		cookie := &http.Cookie{
			Name:     c.Auth.RefreshTokenCookieName,
			Value:    tokens.Refresh,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/api/v1/auth/",
		}

		http.SetCookie(w, cookie)

		writeJSON(w, http.StatusOK, map[string]string{"accessToken": tokens.Access})
	}
}

func refreshEndpoint(logger *slog.Logger, auth core.Auth, c *test_medods.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Refresh endpoint activated")
		refreshToken := getFromCookies(r, c.Auth.RefreshTokenCookieName)
		logger.Debug(refreshToken)
		if refreshToken == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "not authorized"})
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		userAgent := r.Header.Get("User-Agent")
		ipAddr := r.RemoteAddr

		tokens, err := auth.RefreshTokens(ctx, refreshToken, userAgent, ipAddr)
		if err != nil {
			httpErr := validateError(err)
			writeJSON(w, httpErr.status, map[string]string{"message": httpErr.message})
			return
		}

		cookie := &http.Cookie{
			Name:     c.Auth.RefreshTokenCookieName,
			Value:    tokens.Refresh,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}

		http.SetCookie(w, cookie)

		writeJSON(w, http.StatusOK, map[string]string{"accessToken": tokens.Access})
	}
}

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
	}
}

func unauthorizeUserEndpoint(logger *slog.Logger, auth core.Auth, c *test_medods.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		user, ok := userFromContext(ctx)
		if !ok {
			logger.Error("Something went wrong with unauthorizeUserEndpoint")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "server internal error"})
			return
		}
		if err := auth.LogOutUser(ctx, user); err != nil {
			httpErr := validateError(err)
			writeJSON(w, httpErr.status, map[string]string{"message": httpErr.message})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     c.RefreshTokenCookieName,
			Value:    "",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			Path:     "/",
			MaxAge:   -1,
		})

		writeJSON(w, http.StatusOK, map[string]string{"message": "you were unauthorized"})

	}
}

func getFromCookies(r *http.Request, key string) string {
	thingFromCookie, err := r.Cookie(key)
	if err != nil {
		return ""
	}
	return thingFromCookie.Value
}
