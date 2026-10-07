-- The `level` column namespaces users per demo level (0-4).
-- NOTE: level 0 deliberately stores the password in plaintext.
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  level      INTEGER NOT NULL,
  username   TEXT NOT NULL,
  password   TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (level, username)
);

CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);