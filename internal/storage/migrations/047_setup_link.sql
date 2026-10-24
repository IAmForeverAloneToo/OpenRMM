-- Phase 6.2: the one-time link that creates the first administrator in the
-- browser (owner decision: valid 1 hour, single use). Only the token's
-- SHA-256 is kept; a new link replaces the previous one.
CREATE TABLE setup_links (
 id INTEGER PRIMARY KEY CHECK(id=1),
 token_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 used_at INTEGER
);
