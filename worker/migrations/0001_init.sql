-- secure.abramov.vip — interactive API state (variant B).
-- No IP addresses, cookies or persistent visitor identifiers are stored.

-- Aggregated page views per UTC day. event_id '' = all page views; otherwise per Event ID (all languages summed).
CREATE TABLE views_daily (
  day      TEXT    NOT NULL,
  event_id TEXT    NOT NULL DEFAULT '',
  count    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, event_id)
);

-- Short-lived random per-tab session IDs; a session counts as active for 2 minutes after its last heartbeat.
CREATE TABLE active_sessions (
  sid       TEXT    PRIMARY KEY,
  last_seen INTEGER NOT NULL
);
CREATE INDEX idx_active_last_seen ON active_sessions (last_seen);

-- Source suggestions created through the on-site form (idempotency + duplicate check).
CREATE TABLE suggestions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id   TEXT    NOT NULL UNIQUE,
  url_norm     TEXT    NOT NULL UNIQUE,
  issue_number INTEGER,
  issue_url    TEXT,
  status       TEXT    NOT NULL DEFAULT 'pending', -- pending | created
  created_at   INTEGER NOT NULL
);

-- Web Push subscriptions and preferences.
CREATE TABLE push_subscriptions (
  id           TEXT    PRIMARY KEY,           -- SHA-256 of endpoint
  endpoint     TEXT    NOT NULL UNIQUE,
  p256dh       TEXT    NOT NULL,
  auth         TEXT    NOT NULL,
  lang         TEXT    NOT NULL,
  min_priority TEXT    NOT NULL DEFAULT 'high',
  categories   TEXT    NOT NULL DEFAULT '[]',  -- JSON array, empty = all
  products     TEXT    NOT NULL DEFAULT '[]',  -- JSON array, empty = all
  failures     INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);

-- Outbox: one row per (subscription, event, revision). Makes dispatch idempotent and retryable.
CREATE TABLE push_outbox (
  sub_id     TEXT    NOT NULL,
  event_id   TEXT    NOT NULL,
  rev        TEXT    NOT NULL,
  payload    TEXT    NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'pending', -- pending | sent | failed | gone
  attempts   INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (sub_id, event_id, rev)
);
CREATE INDEX idx_outbox_status ON push_outbox (status, attempts);

-- Small key/value state: push watermark, pause switch.
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
