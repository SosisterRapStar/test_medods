-- +goose Up
-- +goose StatementBegin
ALTER TABLE auth.tokens DROP COLUMN issued_to_IP;
ALTER TABLE auth.tokens DROP COLUMN issued_to_UA;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE auth.tokens COLUMN issued_to_IP TEXT;
ALTER TABLE auth.tokens COLUMN issued_to_UA TEXT;
-- +goose StatementEnd
