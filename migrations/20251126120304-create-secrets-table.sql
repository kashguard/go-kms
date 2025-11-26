-- +migrate Up
-- KMS Secret 存储表
CREATE TABLE secrets (
    key_id varchar(255) PRIMARY KEY,
    encrypted_data bytea NOT NULL,
    kms_key_id varchar(255) NOT NULL,
    key_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    FOREIGN KEY (kms_key_id) REFERENCES keys (key_id) ON DELETE RESTRICT
);

CREATE INDEX idx_secrets_kms_key_id ON secrets (kms_key_id);

CREATE INDEX idx_secrets_created_at ON secrets (created_at);

-- +migrate Down
DROP INDEX IF EXISTS idx_secrets_created_at;

DROP INDEX IF EXISTS idx_secrets_kms_key_id;

DROP TABLE IF EXISTS secrets;

