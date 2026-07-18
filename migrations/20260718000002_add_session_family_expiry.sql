-- Absolute cap on refresh-token rotation families. Rotation keeps issuing
-- fresh tokens, but never one valid past its family's expiry, so a session
-- cannot be renewed forever. Existing sessions get the default 90-day cap
-- measured from their creation.
ALTER TABLE auth_sessions
    ADD COLUMN family_expires_at TIMESTAMPTZ;

UPDATE auth_sessions
    SET family_expires_at = created_at + interval '90 days';

ALTER TABLE auth_sessions
    ALTER COLUMN family_expires_at SET NOT NULL;
