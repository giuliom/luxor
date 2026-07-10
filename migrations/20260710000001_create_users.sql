CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_email_normalized CHECK (email = lower(email)),
    CONSTRAINT users_email_not_empty CHECK (length(email) > 3)
);

CREATE UNIQUE INDEX users_email_unique_idx ON users (email);
