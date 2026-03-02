# idap-proxy

Go server implementing the IDAP proxy — public key directory, encrypted inbox, OIDC provider, recovery shard storage, and migration management.

## Role in IDAP

The proxy is the server-side component that clients interact with. It stores public keys, routes encrypted messages, acts as an OIDC provider for the login flow, and holds encrypted recovery shards. It is a "dumb pipe" — all payloads are encrypted client-side. The proxy cannot read inbox messages, contact cards, or recovery shards.

Anyone can run a proxy. Proxies federate automatically via `/.well-known/idap-configuration`.

## API Overview

### Discovery

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/idap-configuration` | IDAP discovery document |
| `GET /.well-known/openid-configuration` | OIDC discovery document |

### Key Management

| Endpoint | Auth | Description |
|----------|------|-------------|
| `PUT /keys/{pubkey}` | Signature (updates) | Register or update key bundle |
| `GET /keys/{pubkey}` | No | Fetch key bundle |
| `GET /jwks` | No | Provider JWKS for JWT verification |

### Inbox

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /inbox/{pubkey}` | Access code or proof | Deliver encrypted message |
| `GET /inbox/{pubkey}` | Signature | List messages (headers only) |
| `GET /inbox/{pubkey}/{id}/payload` | Signature | Fetch message payload |
| `DELETE /inbox/{pubkey}/{id}` | Signature | Delete a message |
| `POST /inbox/{pubkey}/access-code` | Signature | Generate inbox access code |
| `GET /inbox/resolve/{code}` | No | Resolve access code to key bundle |

### Authentication (OIDC)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /auth/login-code` | Signature | Generate login code (5 min TTL) |
| `GET /auth/authorize` | No | Browser login page |
| `POST /auth/authorize` | No | Submit login code |
| `GET /auth/authorize/poll/{id}` | No | Browser polls for approval |
| `GET /ws` | Signature | WebSocket for auth delivery |
| `POST /auth/token` | No | Exchange code for JWT |
| `GET /auth/userinfo` | Bearer | Returns `sub` claim |

### Recovery

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /recovery/shard/{pubkey}` | Signature | Store encrypted shard |
| `GET /recovery/shard/{pubkey}/{id}` | Timed code | Retrieve shard |

### Migration

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /migration/{pubkey}` | No | Fetch migration record |
| `POST /migration/{pubkey}` | Signature | Publish migration |

### Authentication

Authenticated endpoints use three headers:

```
X-IDAP-Key: <base64 public key>
X-IDAP-Signature: <Ed25519 signature over "{METHOD}:{PATH}:{TIMESTAMP}">
X-IDAP-Timestamp: <unix timestamp>
```

## Database Schema

SQLite with 8 tables: `users`, `inbox`, `shards`, `oidc_sessions`, `access_codes`, `migrations`, `used_nonces`, `provider_keys`. Schema is applied automatically on startup (`CREATE TABLE IF NOT EXISTS`).

## Running

### Development

```sh
cd proxy
go run ./cmd/idap-proxy --dev
```

### Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `DB_PATH` | `idap.db` | SQLite file path |
| `HOST` | *(empty)* | Public hostname for discovery docs |
| `LOG_LEVEL` | `info` | Logging level |
| `LOG_FORMAT` | `text` | `text` or `json` |

The `--dev` flag enables relaxed CORS and verbose request logging.

### Production Build

```sh
cd proxy
CGO_ENABLED=1 go build -o idap-proxy ./cmd/idap-proxy
```

`CGO_ENABLED=1` is required for `go-sqlite3`.

### Reverse Proxy

TLS termination should be handled by a reverse proxy (nginx, Caddy). WebSocket upgrade headers (`Upgrade`, `Connection`) must be forwarded for the `/ws` endpoint.

## Dependencies

| Package | Why |
|---------|-----|
| `mattn/go-sqlite3` | SQLite driver (CGO) |
| `gorilla/websocket` | WebSocket support for real-time auth delivery |
| `google/uuid` | UUID generation for sessions and messages |
| `golang.org/x/crypto` | Ed25519 operations |
| `stretchr/testify` | Test assertions |

## Testing

```sh
cd proxy
go test ./...
```

23+ tests covering: key registration and retrieval, OIDC discovery, inbox CRUD, access code generation and resolution, OIDC login code flow, WebSocket auth delivery, shard storage and retrieval, and migration records.

## Status

Implemented: full HTTP API (24 endpoints), Ed25519 signature verification, OIDC login code flow with WebSocket delivery, inbox access codes, dark-themed browser UI for login, structured logging, graceful shutdown. Not yet implemented: rate limiting, federation testing, WebFinger (`/.well-known/webfinger`) (planned).
