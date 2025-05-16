SHELL := /bin/bash
SHELLFLAGS := -c
CURDIR := $(shell pwd)
LOCAL_BIN := $(CURDIR)/bin
export GOBIN := $(LOCAL_BIN)

MIGRATION_PATH := ./migrations
GOOSE_DBSTRING = postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@localhost:5433/$(POSTGRES_DB)
GOOSE_DRIVER = postgres

.ONESHELL:

set-deps:
	go install github.com/pressly/goose/v3/cmd/goose@latest

load_env:
	@source ./set_env

db-status: load_env
	@GOOSE_DRIVER=$(GOOSE_DRIVER) GOOSE_DBSTRING=$(GOOSE_DBSTRING) goose -dir=$(MIGRATION_PATH) status

up: load_env
	@GOOSE_DRIVER=$(GOOSE_DRIVER) GOOSE_DBSTRING=$(GOOSE_DBSTRING) goose -dir=$(MIGRATION_PATH) up

reset: load_env
	@GOOSE_DRIVER=$(GOOSE_DRIVER) GOOSE_DBSTRING=$(GOOSE_DBSTRING) goose -dir=$(MIGRATION_PATH) reset

start-db: load_env
	@docker compose -f docker-compose-db.yaml up -d    

stop-db: load_env
	@docker compose -f docker-compose-db.yaml down

run: load_env
	@go run cmd/main.go

install: load_env
	@go install

.PHONY: set-deps migrate load_env start_db reset up sb-status install run