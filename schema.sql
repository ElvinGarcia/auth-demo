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
-- Level 2 (SMS). ON DELETE CASCADE so removing a user removes their numbers and codes.

-- Which mock "phone" (a browser cookie) currently receives texts for a number.
-- Moving `device` to someone else is what a SIM swap does.
CREATE TABLE IF NOT EXISTS sms_numbers (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  number  TEXT NOT NULL UNIQUE,
  device  TEXT
);

-- The mock carrier: every text the demo "sends" lands here.
CREATE TABLE IF NOT EXISTS sms_outbox (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  number     TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per code sent. Only a keyed hash of the code is stored.
CREATE TABLE IF NOT EXISTS sms_challenges (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sms_challenges_user ON sms_challenges(user_id, created_at);
