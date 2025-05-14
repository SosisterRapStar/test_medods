package internal

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/sosisterrapstar/test_medods"
)

// Not Implemented
func addRoutes(mux *http.ServeMux, logger *slog.Logger, config *test_medods.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { fmt.Println("Not Implemented") }
}
