package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var WEBHOOK_ADDR = os.Getenv("WEBHOOK_ADDR")

type IpUpdateEvent struct {
	Timestamp time.Time `json:"time"`
	UserId    string    `json:"user_id"`
	PrevIp    string    `json:"prev_ip"`
	NewIp     string    `json:"new_ip"`
}

func webhookEndpoint(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		event := IpUpdateEvent{}
		json.NewDecoder(r.Body).Decode(&event)
		logger.Info(
			"EVENT REGISTERED",
			"Timestamp", event.Timestamp,
			"UserId", event.UserId,
			"PrevIp", event.PrevIp,
			"NewIp", event.NewIp)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ACCEPTED"))
	}
}

func initServer(logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/change_ip_event", webhookEndpoint(logger))
	newServer := &http.Server{
		Addr:    WEBHOOK_ADDR,
		Handler: mux,
	}
	return newServer
}

func start(server *http.Server) {
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatal("Error occured server can not be started")
		}
	}()
}

func waitForStop(server *http.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	ctx, cancel := context.WithTimeout(context.Background(), 10)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal("Error shutting the server down")
	}
}

func main() {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{})
	logger := slog.New(handler)
	server := initServer(logger)
	logger.Info(fmt.Sprintf("Starting up the webhook server on %s", WEBHOOK_ADDR))
	start(server)
	waitForStop(server)
	logger.Info("Server is down")

}
