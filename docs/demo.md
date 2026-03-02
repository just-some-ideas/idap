# Demo — OIDC Relying Party

A minimal web application that acts as an OIDC relying party (client) for the IDAP proxy. Use it to test the full authentication flow end-to-end.

---

## What It Does

The demo app is a single-page Go web server that:

1. Shows a "Sign In with IDAP" button
2. Redirects to the proxy's OIDC authorize endpoint
3. Receives the authorization code callback
4. Exchanges the code for tokens at the proxy's token endpoint
5. Displays the resulting JWT claims (sub, aud, exp, etc.)

This is the same flow any website would implement to add IDAP login. The demo exists so you can see it working without building a real integration.

---

## Running

```sh
# Terminal 1 — start the proxy
cd proxy && go run ./cmd/idap-proxy --dev

# Terminal 2 — start the demo
cd demo && go run .
# → http://localhost:9090
```

Then open the iOS app, generate a login code, and enter it on the demo page.

### Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PROXY_URL` | `http://localhost:8080` | Proxy base URL |
| `PORT` | `9090` | Demo server port |

---

## What It Demonstrates

- Standard OIDC authorization code flow against an IDAP proxy
- Token exchange and JWT claim inspection
- How a relying party receives only a `sub` claim (public key) — no PII unless explicitly shared

The demo is intentionally minimal — no session persistence, no database, no TLS. It's a test tool, not a reference for production integration. See [Backlog](backlog.md) for planned integration guides.
