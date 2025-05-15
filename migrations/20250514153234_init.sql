-- +goose Up
-- +goose StatementBegin
CREATE SCHEMA IF NOT EXISTS auth;
CREATE TABLE auth.users(
    user_id UUID PRIMARY KEY,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE auth.tokens(
    user_id UUID references auth.users(user_id) ON DELETE CASCADE,
    token_id UUID PRIMARY KEY,
    token TEXT,
    issued_to_UA TEXT,
    issued_to_IP TEXT, 
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_foreign_key_users ON auth.tokens(user_id);
SET search_path TO auth, public; 
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_foreign_key_users;
DROP TABLE IF EXISTS auth.tokens;
DROP TABLE IF EXISTS auth.users;
DROP SCHEMA IF EXISTS auth;
-- +goose StatementEnd
