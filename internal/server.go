package internal

// the main module for server initializing

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/sosisterrapstar/test_medods"
)

func NewHandler(
	logger *slog.Logger,
	config *test_medods.Config,
	// place for future dependencies
) http.Handler {
	mux := http.NewServeMux()
	addRoutes(
		mux,
		logger,
		config,
	)
	var handler http.Handler = mux
	return handler
}

// Server struct as a wrapper around http.Server
type Server struct {
	logger *slog.Logger
	s      *http.Server
}

func NewServer(
	logger *slog.Logger,
	c *test_medods.Config,
	// place for future dependencies
) *Server {
	handler := NewHandler(logger, c)
	httpServer := &http.Server{
		Addr:    c.Addr,
		Handler: handler,
	}
	return &Server{
		logger: logger,
		s:      httpServer,
	}
}

func (s *Server) Start() {
	go func() {
		s.logger.Info(fmt.Sprintf("Starting the server on %s", s.s.Addr))
		if err := s.s.ListenAndServe(); err != nil {
			log.Fatal("Error starting the server")
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
