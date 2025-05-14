package postgres

import (
	"context"
	"log"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sosisterrapstar/test_medods"
)

type PostgresConnection struct {
	Pool *pgxpool.Pool
}

func (pc *PostgresConnection) Open(logger *slog.Logger, c *test_medods.Config) {
	pgconfig, err := pgxpool.ParseConfig(c.Postgres.Url)
	if err != nil {
		log.Fatal("Error reading dbstring")
	}
	pgconfig.MaxConns = int32(c.Postgres.MaxConns)
	pgconfig.MinConns = int32(c.Postgres.MinConns)

	connPool, err := pgxpool.NewWithConfig(context.Background(), pgconfig)
	if err != nil {
		log.Fatal("Error creating postgresql conn pool")
	}
	pc.Pool = connPool
	logger.Debug("Created and opend postgres pool")
}

func (pc *PostgresConnection) Close(logger *slog.Logger) {
	logger.Debug("Started to cloe pgx pool")
	pc.Pool.Close()
	logger.Debug("DB pool closed")
}
