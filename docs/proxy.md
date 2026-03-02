# Proxy — Reference Implementation

The proxy is the reference server implementation. It provides key discovery, message routing, OIDC provider services, and shard storage as a single deployable binary.

This document describes the implementation — why these choices were made and how it works. For the protocol-level specification of what any server must do, see [Protocol Specification](protocol.md).

---

## Overview

The proxy is a "dumb pipe." It routes messages and serves public keys but cannot read anything it stores. All inbox messages, recovery shards, and contact cards are encrypted client-side before reaching the proxy. A compromised proxy reveals timing metadata but no content.

This also makes self-hosting safe — a self-hosted proxy with poor security practices still can't leak what it can't read.

---

## Why Go

Go compiles to a single static binary with no runtime dependencies. `go build` produces something you can `scp` to a server and run. The stdlib includes a production-quality HTTP server, WebSocket support is mature (gorilla/websocket), and SQLite has a stable cgo binding.

The language is simple enough that anyone can read and audit the proxy code. That matters for a component that handles identity infrastructure.

**Tradeoffs:** Go's error handling is verbose. The proxy uses `modernc.org/sqlite`, a pure-Go SQLite driver, so `go build` produces a static binary with zero C dependencies — cross-compilation just works (`GOOS=linux GOARCH=amd64 go build`).

---

## Why SQLite

SQLite is a single file, requires no separate daemon, and handles the proxy's workload easily. Self-hosters can run the proxy as a single binary with no database infrastructure.

**Tradeoffs:** SQLite's write concurrency is limited to one writer at a time. For a proxy serving hundreds of users, this is fine. For thousands of concurrent writers, PostgreSQL would be needed. PostgreSQL support is [planned](backlog.md).

---

## Single Binary, All Endpoints

The proxy serves key directory, OIDC provider, inbox, and shard storage from one process. These are conceptually distinct concerns but practically they share a database and a deploy target.

For self-hosters, one binary is one thing to deploy. Splitting into separate services is straightforward if needed — the HTTP endpoints are already cleanly separated by concern.

**Tradeoffs:** All-or-nothing deployment. A self-hoster who only wants key discovery still gets inbox and OIDC. The overhead is minimal.

---

## What the Proxy Can and Cannot See

**Can observe:**
- Public key existence and registration timing
- Service names in OIDC sessions (from `client_id`)
- Inbox message delivery timing (not content)
- IP addresses of connecting clients
- Correlation of personas by IP if registered at the same proxy

**Cannot observe:**
- Inbox message content (encrypted client-side)
- Recovery shard content (encrypted client-side)
- Contact card content (encrypted client-side)
- Persona linkage across different proxies

**Cannot do:**
- Forge authentication assertions (JWTs are signed by the user's key)
- Decrypt anything it stores

See [Threat Model](threat-model.md) for a full analysis.

---

## Endpoints

See [Protocol Specification — Endpoint Reference](protocol.md#endpoint-reference) for the full endpoint table.

---

## Running

```sh
# Development mode (in-memory DB, verbose logging)
cd proxy && go run ./cmd/idap-proxy --dev

# Production
cd proxy && go build -o idap-proxy ./cmd/idap-proxy
HOST=https://idap.example.com DB_PATH=/var/lib/idap/idap.db ./idap-proxy
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `http://<request host>` | Public URL — used in OIDC discovery (`issuer`, endpoints). Must be set for production. |
| `PORT` | `8080` | Listen port |
| `DB_PATH` | `idap.db` | SQLite database file path |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `text` | `text` or `json` |

### Deploying Behind a Reverse Proxy (nginx)

The proxy uses WebSockets for real-time push notifications to the app. If you're running behind nginx (or any reverse proxy), you **must** forward the WebSocket upgrade headers or the app won't receive auth requests.

```nginx
server {
    listen 443 ssl;
    server_name idap.example.com;

    # TLS (e.g. Let's Encrypt)
    ssl_certificate     /etc/letsencrypt/live/idap.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/idap.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket — required for auth request push notifications
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

Without the `/ws` location block, the app will register and poll normally but won't receive real-time auth request notifications. The proxy log will show: `ws upgrade failed ... 'upgrade' token not found in 'Connection' header`.

## Testing

```sh
cd proxy && go test ./...
```

---

## Source Layout

```
proxy/
├── cmd/idap-proxy/     Entry point
├── internal/
│   ├── db/             Database layer (SQLite, schema)
│   ├── handlers/       HTTP handlers (keys, inbox, OIDC, recovery)
│   └── auth/           Request signature verification
├── go.mod
└── go.sum
```
