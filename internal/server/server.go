package server

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"log/slog"
// 	"net/http"
// 	"time"

// 	"github.com/sosisterrapstar/test_medods"
// )

// type Server struct {
// 	logger *slog.Logger
// 	server *http.Server
// 	router *http.ServeMux
// }

// func NewServer(c *test_medods.Config, logger *slog.Logger, mux *http.ServeMux) *Server {
// 	s := &http.Server{
// 		Addr:           c.Server.Addr,
// 		Handler:        mux,
// 		ReadTimeout:    10 * time.Second,
// 		WriteTimeout:   10 * time.Second,
// 		MaxHeaderBytes: 1 << 20,
// 	}
// 	return &Server{logger: logger, server: s, router: mux}
// }

// func (s *Server) Start() {
// 	go func() {
// 		s.logger.Info(fmt.Sprintf("Starting the server on %s", s.server.Addr))
// 		if err := s.server.ListenAndServe(); err != nil {
// 			log.Fatal("Something went wrong with http server starting")
// 		}
// 		s.logger.Info("Server is shutting down")
// 	}()
// }

// func (s *Server) Stop(ctx context.Context) {
// 	if err := s.server.Shutdown(ctx); err != nil {
// 		log.Fatal("Error occured shutting the server down")
// 	}
// 	s.logger.Info("Server was stoped")
// }
