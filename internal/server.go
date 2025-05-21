package internal

// the main module for server initializing

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	tas "github.com/sosisterrapstar/token_auth_service"
	_ "github.com/sosisterrapstar/token_auth_service/docs"
	"github.com/sosisterrapstar/token_auth_service/internal/core"
	httpSwagger "github.com/swaggo/http-swagger/v2"
)

func NewServeMuxHandler(
	logger *slog.Logger,
	config *tas.Config,
	auth core.Auth,
) *http.ServeMux {
	mux := http.NewServeMux()
	addRoutes(
		mux,
		logger,
		config,
		auth,
	)
	addSwagger(mux)
	return mux
}

func addSwagger(mux *http.ServeMux) {
	mux.Handle("GET /swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))
}

// Server struct as a wrapper around http.Server
type Server struct {
	logger *slog.Logger
	s      *http.Server
	Mux    *http.ServeMux // чтобы потом можно было подсоединять сторонние роуты к серверу
}

func NewServer(
	logger *slog.Logger,
	c *tas.Config,
	auth core.Auth,
) *Server {
	mux := NewServeMuxHandler(logger, c, auth)
	var handler http.Handler = mux
	httpServer := &http.Server{
		Addr:    c.Addr,
		Handler: handler,
	}
	return &Server{
		logger: logger,
		s:      httpServer,
		Mux:    mux,
	}
}

func (s *Server) Start() {
	go func() {
		s.logger.Info(fmt.Sprintf("Starting the server on %s", s.s.Addr))
		if err := s.s.ListenAndServe(); err != nil {
			log.Fatal("Error starting the server", "err", err.Error())
		}
		log.Fatal("Started to stop the server")
	}()
}

func (s *Server) Stop(ctx context.Context) {
	if err := s.s.Shutdown(ctx); err != nil {
		log.Fatalf("Error occured during server shutdown on %s", s.s.Addr)
	}
	s.logger.Info("Server stopped")
}
