-- Phase 3d: the response tool library. Tools are files the owner uploads
-- (such as Autoruns or a memory capture tool), stored by SHA-256 in the
-- evidence store, that a case can drop onto a device. A withdrawn tool can no
-- longer be dropped; its file stays, as custody entries may name it.
CREATE TABLE response_tools (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0),
  actor TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  withdrawn_at INTEGER
);
