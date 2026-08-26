CREATE TABLE IF NOT EXISTS sessions (
    key       TEXT PRIMARY KEY,
    hwid      TEXT,
    pc_name   TEXT,
    username  TEXT,
    created   INTEGER,
    last_seen INTEGER,
    active    INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key  TEXT NOT NULL,
    type         TEXT,
    title        TEXT,
    description  TEXT,
    severity     TEXT,
    timestamp    INTEGER,
    FOREIGN KEY (session_key) REFERENCES sessions(key)
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_key);
