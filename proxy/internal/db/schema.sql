CREATE TABLE IF NOT EXISTS users (
    pubkey TEXT PRIMARY KEY,
    pubkey_bundle TEXT NOT NULL,
    signing_key TEXT,
    profile_json TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS inbox (
    id TEXT PRIMARY KEY,
    recipient TEXT NOT NULL,
    header BLOB NOT NULL,
    payload BLOB,
    delivered_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS shards (
    id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    encrypted_blob BLOB NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS oidc_sessions (
    id TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    service TEXT NOT NULL,
    nonce TEXT NOT NULL,
    number_match INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    approved INTEGER NOT NULL DEFAULT 0,
    signed_assertion TEXT
);

CREATE TABLE IF NOT EXISTS access_codes (
    code TEXT PRIMARY KEY,
    pubkey TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS migrations (
    pubkey TEXT PRIMARY KEY,
    signed_record TEXT NOT NULL,
    published_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS used_nonces (
    nonce TEXT PRIMARY KEY,
    used_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS provider_keys (
    id TEXT PRIMARY KEY,
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_inbox_recipient ON inbox(recipient);
CREATE INDEX IF NOT EXISTS idx_shards_pubkey ON shards(pubkey);
CREATE INDEX IF NOT EXISTS idx_oidc_pubkey ON oidc_sessions(pubkey);
CREATE INDEX IF NOT EXISTS idx_access_codes_pubkey ON access_codes(pubkey);
