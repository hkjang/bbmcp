-- bbmcp initial schema.

CREATE TABLE IF NOT EXISTS users (
    id                BIGSERIAL PRIMARY KEY,
    username          VARCHAR(255) NOT NULL UNIQUE,
    email             VARCHAR(320),
    display_name      VARCHAR(255),
    password_hash     TEXT,
    keycloak_sub      VARCHAR(255) UNIQUE,
    is_service_admin  BOOLEAN NOT NULL DEFAULT FALSE,
    roles             TEXT[] NOT NULL DEFAULT '{}',
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    source            VARCHAR(20) NOT NULL DEFAULT 'local',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS web_sessions (
    id          UUID PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    ip          VARCHAR(64),
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS web_sessions_user_idx ON web_sessions(user_id);

-- Runtime settings. Secret values are stored AES-256-GCM sealed in value_enc.
CREATE TABLE IF NOT EXISTS settings (
    key         VARCHAR(128) PRIMARY KEY,
    value_json  JSONB,
    value_enc   TEXT,
    is_secret   BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS bitbucket_identity_mapping (
    id                  BIGSERIAL PRIMARY KEY,
    keycloak_sub        VARCHAR(255) NOT NULL UNIQUE,
    keycloak_username   VARCHAR(255) NOT NULL,
    bitbucket_user_id   BIGINT NOT NULL UNIQUE,
    bitbucket_username  VARCHAR(255) NOT NULL,
    bitbucket_email     VARCHAR(320),
    bitbucket_display   VARCHAR(255),
    mapping_type        VARCHAR(20) NOT NULL DEFAULT 'auto',
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    last_error          TEXT,
    mapped_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at         TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Failed or pending mapping attempts, surfaced in the admin UI.
CREATE TABLE IF NOT EXISTS identity_mapping_errors (
    id                BIGSERIAL PRIMARY KEY,
    keycloak_sub      VARCHAR(255) NOT NULL,
    keycloak_username VARCHAR(255) NOT NULL,
    reason            TEXT NOT NULL,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Key permission scheme: editable roles granting scopes to personal API keys.
CREATE TABLE IF NOT EXISTS key_roles (
    name        VARCHAR(64) PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    builtin     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id             UUID PRIMARY KEY,
    user_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           VARCHAR(255) NOT NULL,
    prefix         VARCHAR(32) NOT NULL UNIQUE,
    key_hmac       TEXT NOT NULL,
    key_role       VARCHAR(64) REFERENCES key_roles(name) ON DELETE SET NULL,
    scopes         TEXT[] NOT NULL DEFAULT '{}',
    rotated_from   UUID,
    rotation_due_at TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT
);
CREATE INDEX IF NOT EXISTS api_keys_user_idx ON api_keys(user_id);

-- Optional per-user Bitbucket personal access token (User Mode attribution).
CREATE TABLE IF NOT EXISTS user_bitbucket_pat (
    user_id        BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    bitbucket_user VARCHAR(255) NOT NULL,
    pat_enc        TEXT NOT NULL,
    verified_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- MCP tool registry. Rows are reconciled from code on boot; admin edits persist.
CREATE TABLE IF NOT EXISTS mcp_tools (
    name              VARCHAR(128) PRIMARY KEY,
    title             VARCHAR(255) NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    tool_group        VARCHAR(64) NOT NULL DEFAULT 'general',
    risk_level        VARCHAR(16) NOT NULL DEFAULT 'READ',
    required_perm     VARCHAR(32) NOT NULL DEFAULT 'REPO_READ',
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    min_role          VARCHAR(64) NOT NULL DEFAULT 'bitbucket-mcp-user',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ACL over projects / repositories / branches, evaluated on top of Bitbucket.
CREATE TABLE IF NOT EXISTS policy_rules (
    id          BIGSERIAL PRIMARY KEY,
    kind        VARCHAR(16) NOT NULL,
    pattern     VARCHAR(255) NOT NULL,
    effect      VARCHAR(8) NOT NULL,
    risk_cap    VARCHAR(16),
    priority    INT NOT NULL DEFAULT 100,
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_requests (
    id              UUID PRIMARY KEY,
    keycloak_sub    VARCHAR(255) NOT NULL,
    user_id         BIGINT REFERENCES users(id) ON DELETE SET NULL,
    username        VARCHAR(255) NOT NULL,
    tool_name       VARCHAR(128) NOT NULL,
    arguments_hash  VARCHAR(64) NOT NULL,
    arguments_redacted JSONB,
    resource        VARCHAR(512) NOT NULL DEFAULT '',
    pr_version      INT,
    status          VARCHAR(20) NOT NULL,
    decided_by      VARCHAR(255),
    decision_note   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    approved_at     TIMESTAMPTZ,
    consumed_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS approval_status_idx ON approval_requests(status, expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id                 BIGSERIAL PRIMARY KEY,
    occurred_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    category           VARCHAR(32) NOT NULL,
    action             VARCHAR(128) NOT NULL,
    keycloak_sub       VARCHAR(255),
    keycloak_username  VARCHAR(255),
    bitbucket_user_id  BIGINT,
    bitbucket_username VARCHAR(255),
    service_account    VARCHAR(255),
    mcp_client         VARCHAR(255),
    auth_mode          VARCHAR(32),
    tool_name          VARCHAR(128),
    project_key        VARCHAR(128),
    repository         VARCHAR(255),
    pull_request       INT,
    approval_id        UUID,
    success            BOOLEAN NOT NULL DEFAULT TRUE,
    error_code         VARCHAR(64),
    message            TEXT,
    latency_ms         INT,
    ip                 VARCHAR(64),
    detail             JSONB
);
CREATE INDEX IF NOT EXISTS audit_time_idx ON audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_cat_idx ON audit_log(category, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_user_idx ON audit_log(keycloak_username, occurred_at DESC);

CREATE TABLE IF NOT EXISTS mcp_sessions (
    id          UUID PRIMARY KEY,
    user_id     BIGINT REFERENCES users(id) ON DELETE CASCADE,
    username    VARCHAR(255) NOT NULL,
    client_name VARCHAR(255) NOT NULL DEFAULT '',
    auth_mode   VARCHAR(32) NOT NULL DEFAULT 'oauth',
    ip          VARCHAR(64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at   TIMESTAMPTZ
);
