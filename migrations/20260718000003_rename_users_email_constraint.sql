-- The original name suggested a non-empty check, but the constraint enforces
-- a minimum length; name it for what it does.
ALTER TABLE users RENAME CONSTRAINT users_email_not_empty TO users_email_min_length;
