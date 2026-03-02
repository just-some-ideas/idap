# idap-auth

OIDC authentication logic for the IDAP protocol — auth request parsing, JWT signing, WebSocket sessions, and pre-authorization.

## Role in IDAP

Implements the client side of IDAP's app-initiated OIDC flow. Parses incoming auth requests (from push notifications or WebSocket), builds EdDSA JWTs signed by the persona's key, manages real-time WebSocket connections to the proxy for auth delivery, and handles pre-authorization for trusted services.

## API Overview

### Key Types

```swift
struct AuthRequest: Codable {
    let requestId: String
    let service: String
    let serviceDisplayName: String
    let personaHint: String?
    let requesting: [String]
    let nonce: String
    let expiresAt: Date
    let locationHint: String?
}

struct SignedAssertion {
    let jwt: String              // EdDSA-signed JWT
    let requestId: String
}

struct PreAuth {
    let id: String
    let service: String
    let personaId: String
    let expiresAt: Date
}
```

### Auth Request Handling

```swift
let auth = try IDAPAuth(db: databaseQueue)

// Parse from APNs push payload
let request = auth.parseAuthRequest(pushUserInfo)

// Approve — signs EdDSA JWT with persona key
let assertion = auth.approveAuthRequest(request, persona: persona, seed: seed)
// assertion.jwt contains the signed JWT
```

### Login Codes

```swift
let loginCode = try await auth.requestLoginCode(persona: persona, seed: seed)
// loginCode.code = "7K3M9X", loginCode.expiresIn = 300
```

### WebSocket Sessions

```swift
let session = IDAPWebSocketSession(auth: auth, connector: connector)
session.onAuthRequest = { request in
    // handle incoming auth request
}
session.connect(url: proxyWSURL, persona: persona, seed: seed)
session.submitAssertion(assertion)
session.disconnect()
```

The WebSocket connection is authenticated via `X-IDAP-Signature`, `X-IDAP-PublicKey`, and `X-IDAP-Timestamp` headers. Automatic reconnection with configurable backoff is built in.

### Pre-Authorization

```swift
// Auto-approve a trusted service for a time period
let preAuth = auth.createPreAuthorization(service: "gamesite.com", persona: persona, seed: seed, ttl: 86400 * 7)

// Check if a service is pre-authorized
if let existing = auth.checkPreAuthorization(service: "gamesite.com", persona: persona) {
    // auto-approve
}
```

### JWT Format

The JWT uses EdDSA (Ed25519) algorithm with the persona's public key embedded in the header:

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<base64url>" }
}
```

Payload includes `sub`, `aud`, `nonce`, `iat`, `exp`, and `request_id`.

## Dependencies

| Package | Why |
|---------|-----|
| `idap-crypto` | Ed25519 signing for JWTs and WebSocket auth |
| `idap-identity` | Persona model and key derivation |
| `GRDB.swift` | SQLite storage for pre-authorizations |

## Testing

```sh
cd packages/idap-auth
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

19 tests covering: auth request parsing, JWT creation and structure, signature verification, WebSocket connection and reconnection, pre-authorization CRUD, login code requests, and PII request parsing.

## Status

Implemented: auth request parsing, EdDSA JWT signing, WebSocket sessions with backoff, pre-authorization, login code generation. Not yet implemented: passkey registration (WebAuthn), PII request approval with encryption.
