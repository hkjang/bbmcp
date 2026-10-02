-- Per-user preferences for the personal (non-admin) pages.
CREATE TABLE IF NOT EXISTS user_prefs (
    user_id        BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    prefer_user_pat BOOLEAN NOT NULL DEFAULT FALSE,
    theme          VARCHAR(16) NOT NULL DEFAULT 'system',
    font_scale     NUMERIC(3,2) NOT NULL DEFAULT 1.00,
    locale         VARCHAR(8) NOT NULL DEFAULT 'ko',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
