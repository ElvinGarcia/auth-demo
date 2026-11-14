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

-- Level 3 (email). The mock mail system: addresses, an outbox, and who can open which mailbox.
-- All addresses end in .invalid, a reserved TLD that can never receive real mail.
CREATE TABLE IF NOT EXISTS email_addresses (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  address TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS email_outbox (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  address    TEXT NOT NULL,
  subject    TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Which browsers have the mailbox open. Unlike a phone number, any number of
-- people can hold a mailbox at once (anyone who learns its password).
CREATE TABLE IF NOT EXISTS mailbox_grants (
  device  TEXT NOT NULL,
  address TEXT NOT NULL,
  PRIMARY KEY (device, address)
);

CREATE TABLE IF NOT EXISTS email_challenges (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_email_challenges_user ON email_challenges(user_id, created_at);

-- Level 4 (TOTP).
-- The secret is stored in PLAINTEXT on purpose: the server must be able to compute the same
-- codes as the user's app, so it has to keep the secret in a usable form. The attacker view
-- shows what a database leak means for a shared-secret factor.
CREATE TABLE IF NOT EXISTS totp_secrets (
  user_id   INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret    TEXT NOT NULL,
  confirmed INTEGER NOT NULL DEFAULT 0,   -- 1 once the user has proven their app works
  last_step INTEGER NOT NULL DEFAULT 0    -- last accepted 30-second step: a code works once
);

-- One row per password-verified login attempt waiting for its code. Caps guessing.
CREATE TABLE IF NOT EXISTS totp_challenges (
  id         TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 0,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_totp_challenges_user ON totp_challenges(user_id, created_at);
