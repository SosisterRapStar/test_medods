package test_medods

import (
	"log/slog"
	"os"
)

type ServerConfig struct {
	Addr string
}

type Config struct {
	Server ServerConfig
}

func NewConfig() *Config {
	return &Config{}
}

func setupLogger() *slog.Logger {

	log := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true}),
	)
	return log
}

var logger = setupLogger()

func GetLogger() *slog.Logger {
	return logger
}
