package test_medods

import (
	"log"
	"log/slog"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

type Auth struct {
	SecretKey                       string `yaml:"secret_key" env-required:"true"`
	AccessTokenExpirePeriodMinutes  int    `yaml:"access_expire_period_minutes" env-default:"3"`
	RefreshTokenExpirePeriodMinutes int    `yaml:"refresh_token_expire_period_minutes" env-default:"10"`
	RefreshTokenCookieName          string `yaml:"refresh_token_cookie_name" env-default:"medods_app_refresh_token"`
	IPChangeNotificationWebhook     string `yaml:"ip_change_notification_webhook" env-default:"http://localhost:9999/api/v1/change_ip_event"`
}

type Server struct {
	Addr       string `yaml:"address" env-required:"true"`
	APIVersion string `yaml:"api_version" env-default:"1"`
}

type Postgres struct {
	Url      string `yaml:"url" env-required:"true"`
	MaxConns int    `yaml:"max_conns" env-default:"10"`
	MinConns int    `yaml:"min_conns" env-default:"3"`
}

type Storage struct {
	Postgres `yaml:"postgres"`
}

type Config struct {
	Env     string `yaml:"env" env-default:"local"`
	Server  `yaml:"http_server"`
	Storage `yaml:"storage"`
	Auth    `yaml:"auth"`
}

func MustLoad() *Config {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		log.Fatal("Config path is not set")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Fatalf("Config file %s doesn't exist", configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		log.Fatal("Can not read config")
	}

	return &cfg
}

func SetupLogger() *slog.Logger {
	log := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug, AddSource: true}),
	)
	return log
}
