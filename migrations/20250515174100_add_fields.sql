-- +goose Up
-- +goose StatementBegin
ALTER TABLE auth.users ADD last_logout TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE auth.tokens ADD is_revoked BOOLEAN DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE auth.users DROP COLUMN last_logout;
ALTER TABLE auth.tokens DROP COLUMN is_revoked;
-- +goose StatementEnd
