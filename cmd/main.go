package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	tas "github.com/sosisterrapstar/token_auth_service"
	"github.com/sosisterrapstar/token_auth_service/internal"
	"github.com/sosisterrapstar/token_auth_service/internal/auth"
	"github.com/sosisterrapstar/token_auth_service/internal/postgres"
	"github.com/sosisterrapstar/token_auth_service/internal/webhook"
)

func main() {
	config := tas.MustLoad()
	logger := tas.SetupLogger(config)
	psConn := postgres.PostgresConnection{}
	psConn.Open(logger, config)

	var webhookService *webhook.IpWebhook
	switch config.Auth.IPChangeNotificationWebhook {
	case "":
		webhookService = nil
	default:
		webhookService = webhook.NewIpWebhook(
			config.Auth.IPChangeNotificationWebhook,
			internal.NewHTTPClient(),
			logger,
		)
		logger.Debug("Registered webhook", "struct", webhookService.Endpoint)

	}

	authService := auth.NewAuthService(logger, config, &psConn, webhookService)

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
