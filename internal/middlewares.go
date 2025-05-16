package internal

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/sosisterrapstar/test_medods/internal/core"
)

type userKey int

const userStructKey = 0

func userFromContext(ctx context.Context) (*core.User, bool) {
	user, ok := ctx.Value(userStructKey).(*core.User)
	return user, ok

}

// func refreshTokenMiddleware(h http.HandlerFunc, auth core.Auth) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		refreshToken := getFromCookies(r, "refresh_token")
// 		if refreshToken == "" {
// 			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "not authorized"})
// 		}
// 		user, err :=
// 		// ctx := context.WithValue(context.Background(), )
// 	}
// }

// Not implemented yet
func authenticationMiddleware(h http.HandlerFunc, auth core.Auth) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "authorization header is required"})
			return
		}

		parts := strings.Fields(authHeader)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "invalid authorization header format"})
			return
		}
		token := parts[1]

		if len(token) == 0 {
			response := map[string]string{"message": "not authorized"}
			writeJSON(w, http.StatusUnauthorized, response)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		user, err := auth.AuthenticateUser(ctx, token)
		if err != nil {
			httpErr := validateError(err)
			writeJSON(w, httpErr.status, map[string]string{"message": httpErr.message})
			return
		}
		cancel()

		ctx = context.WithValue(context.Background(), userStructKey, user)
		h(w, r.WithContext(ctx))
	}
}
