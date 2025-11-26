-- +migrate Up
-- KMS 密钥元数据表
CREATE TABLE keys (
    key_id varchar(255) PRIMARY KEY,
    alias varchar(255) UNIQUE,
    description text,
    key_type varchar(50) NOT NULL,
    key_state varchar(50) NOT NULL,
    key_spec jsonb,
    hsm_handle varchar(255) NOT NULL,
    policy_id varchar(255),
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    deletion_date timestamptz,
    tags jsonb
);

CREATE INDEX idx_keys_alias ON keys (alias);

CREATE INDEX idx_keys_state ON keys (key_state);

CREATE INDEX idx_keys_created_at ON keys (created_at);

CREATE INDEX idx_keys_key_type ON keys (key_type);

CREATE INDEX idx_keys_policy_id ON keys (policy_id);

-- KMS 密钥版本表
CREATE TABLE key_versions (
    key_id varchar(255) NOT NULL,
    version integer NOT NULL,
    hsm_handle varchar(255) NOT NULL,
    is_primary boolean NOT NULL DEFAULT FALSE,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (key_id, version),
    FOREIGN KEY (key_id) REFERENCES keys (key_id) ON DELETE CASCADE
);

CREATE INDEX idx_key_versions_key_id ON key_versions (key_id);

CREATE INDEX idx_key_versions_is_primary ON key_versions (key_id, is_primary)
WHERE
    is_primary = TRUE;

-- KMS 策略表
CREATE TABLE policies (
    policy_id varchar(255) PRIMARY KEY,
    description text,
    policy_document jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_policies_created_at ON policies (created_at);

-- KMS 审计日志表
CREATE TABLE audit_logs (
    id bigserial PRIMARY KEY,
    timestamp timestamptz NOT NULL DEFAULT NOW(),
    event_type varchar(50) NOT NULL,
    user_id varchar(255),
    key_id varchar(255),
    operation varchar(50) NOT NULL,
    result varchar(50) NOT NULL,
    details jsonb,
    ip_address varchar(50)
);

CREATE INDEX idx_audit_timestamp ON audit_logs (timestamp);

CREATE INDEX idx_audit_key_id ON audit_logs (key_id);

CREATE INDEX idx_audit_user_id ON audit_logs (user_id);

CREATE INDEX idx_audit_event_type ON audit_logs (event_type);

CREATE INDEX idx_audit_operation ON audit_logs (operation);

-- +migrate Down
DROP INDEX IF EXISTS idx_audit_operation;

DROP INDEX IF EXISTS idx_audit_event_type;

DROP INDEX IF EXISTS idx_audit_user_id;

DROP INDEX IF EXISTS idx_audit_key_id;

DROP INDEX IF EXISTS idx_audit_timestamp;

DROP TABLE IF EXISTS audit_logs;

DROP INDEX IF EXISTS idx_policies_created_at;

DROP TABLE IF EXISTS policies;

DROP INDEX IF EXISTS idx_key_versions_is_primary;

DROP INDEX IF EXISTS idx_key_versions_key_id;

DROP TABLE IF EXISTS key_versions;

DROP INDEX IF EXISTS idx_keys_policy_id;

DROP INDEX IF EXISTS idx_keys_key_type;

DROP INDEX IF EXISTS idx_keys_created_at;

DROP INDEX IF EXISTS idx_keys_state;

DROP INDEX IF EXISTS idx_keys_alias;

DROP TABLE IF EXISTS keys;

