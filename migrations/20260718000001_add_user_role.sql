-- Demo authorization roles. The default backfills existing accounts as
-- regular users; the grants carried by each role live in the in-memory
-- permission store, not in the database.
ALTER TABLE users
    ADD COLUMN role TEXT NOT NULL DEFAULT 'user',
    ADD CONSTRAINT users_role_known CHECK (role IN ('admin', 'user'));
