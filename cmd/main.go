package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sosisterrapstar/test_medods"
	"github.com/sosisterrapstar/test_medods/internal"
	"github.com/sosisterrapstar/test_medods/internal/auth"
	"github.com/sosisterrapstar/test_medods/internal/postgres"
)

func main() {
	config := test_medods.MustLoad()
	logger := test_medods.SetupLogger()
	psConn := postgres.PostgresConnection{}
	psConn.Open(logger, config)
	authService := auth.NewAuthService(logger, config, &psConn)
	server := internal.NewServer(logger, config, authService)
	server.Start()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	logger.Info("Received Interrupt signal, started to shutdown gracefully")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	server.Stop(ctx)
}
