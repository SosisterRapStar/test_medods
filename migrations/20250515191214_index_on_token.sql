-- +goose Up
-- +goose StatementBegin
CREATE INDEX token_content_index ON auth.tokens(sign_hash);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP  INDEX IF EXISTS token_content_index;
-- +goose StatementEnd
