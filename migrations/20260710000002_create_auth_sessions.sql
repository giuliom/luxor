CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by UUID REFERENCES auth_sessions(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT auth_sessions_token_hash_hex CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

CREATE UNIQUE INDEX auth_sessions_token_hash_unique_idx ON auth_sessions (token_hash);
CREATE INDEX auth_sessions_user_active_idx
    ON auth_sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX auth_sessions_family_idx ON auth_sessions (family_id);
