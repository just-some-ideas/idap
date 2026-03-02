# IDAP — Identity & Attestation Protocol

An open protocol for key-based identity, authentication, attestation, and messaging. A public key is an identity. How it's generated, stored, or managed is not the protocol's concern.

https://github.com/user-attachments/assets/f3f2b4bd-cf04-4145-9b83-2055c1e0ad3c

## What It Defines

IDAP specifies the interfaces for five capabilities:

- **Identity.** A public key from a [supported signing algorithm](docs/protocol.md#signing-algorithms) is an identity. No usernames, no handles, no registration required.
- **Discovery.** Given a public key, find its endpoint and key material. [Wire format and endpoints](docs/protocol.md#key-discovery).
- **Authentication.** Prove control of a key to a service. [OIDC-compatible flow](docs/protocol.md#authentication-oidc) for today's web, [direct key-based auth](docs/protocol.md#key-based-access) for services that support it.
- **Attestation.** Authorities make verifiable claims about identities. Services verify claims without contacting the authority. [W3C VC-compatible credentials](docs/protocol.md#attestation-model) with support for zero-knowledge proofs.
- **Messaging.** Encrypted, asynchronous message delivery between identities. [Envelope format and delivery semantics](docs/protocol.md#messaging-inbox).

The protocol defines shapes, not materials. It doesn't mandate specific cryptographic algorithms, key storage mechanisms, or recovery strategies. Implementations make those choices. See [Philosophy](docs/philosophy.md).

## Design Principles

**Unopinionated.** The protocol doesn't care how you use it. A privacy-maximalist app and a transparent enterprise directory both speak IDAP. See [Philosophy](docs/philosophy.md).

**Composition, not invention.** IDAP composes proven standards (EdDSA, X3DH, W3C VCs, OIDC, AES-GCM) rather than inventing new ones. The novelty is in the glue. See [Philosophy — Composition](docs/philosophy.md#composition-not-invention).

**Pragmatic bridges.** Some components (OIDC flow, proxy, inbox) exist because today's infrastructure requires them. They're designed to be replaceable. See [Pragmatic Compromises](docs/compromises.md).

## Project Status

**Working prototype.** A reference implementation with 6 Swift packages, a Go proxy, and an iOS app — 142+ tests passing. The core flows (identity, OIDC auth, contact exchange, recovery) are implemented and tested.

This is a design-phase prototype seeking review, not production software. See [Backlog](docs/backlog.md) for what's still needed.

## Quick Start

### Run all Swift package tests

```sh
for pkg in packages/idap-crypto packages/idap-identity packages/idap-auth packages/idap-contacts packages/idap-recovery; do
  echo "=== $pkg ==="
  (cd "$pkg" && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test)
done
```

### Run Go proxy tests

```sh
cd proxy && go test ./...
```

### Start the proxy locally

```sh
cd proxy && go run ./cmd/idap-proxy --dev
# → http://localhost:8080/health → {"status":"ok"}
```

### Run the OIDC demo client

```sh
# In one terminal — start the proxy:
cd proxy && go run ./cmd/idap-proxy --dev

# In another — start the demo relying party:
cd demo && go run .
# → http://localhost:9090 — click "Sign In with IDAP"
```

### Deploy the proxy to a server

```sh
# Cross-compile for Linux (from macOS — no C toolchain needed)
cd proxy && GOOS=linux GOARCH=amd64 go build -o idap-proxy-linux-amd64 ./cmd/idap-proxy

# Copy to your server
scp idap-proxy-linux-amd64 user@yourserver:~/idap-proxy

# On the server
chmod +x ~/idap-proxy
HOST=https://idap.yourdomain.com DB_PATH=./idap.db ./idap-proxy --dev
```

If running behind nginx, you **must** configure WebSocket support for the `/ws` path or the app won't receive real-time auth requests. See [Deploying Behind a Reverse Proxy](docs/proxy.md#deploying-behind-a-reverse-proxy-nginx).

### iOS app

```sh
cd ios && xcodegen generate && open IDAP.xcodeproj
# Cmd+U to run unit tests
# Cmd+R to run on simulator or device
```

#### Try it on a real device

1. Open `IDAP.xcodeproj` in Xcode
2. Select your iPhone from the device dropdown
3. Set your Apple ID as the signing team (Target > Signing & Capabilities)
4. Cmd+R to build and run
5. On your phone: Settings > General > VPN & Device Management > trust the developer certificate

A free Apple Developer account works — no paid enrollment required.

#### First launch: Create your identity

1. **Get Started** — generates your master seed and encrypts it with the Secure Enclave
2. **Recovery phrase** — write down the 24 words (or skip for now). This is your only backup.
3. **Create a persona** — give it a name (e.g. "personal"). This derives an Ed25519 key pair from your seed.
4. **Set your proxy URL** — tap the persona, go to details, set the proxy to your server (e.g. `https://idap.yourdomain.com`). This registers your public key and connects the WebSocket for push notifications.

#### Test the OIDC flow

1. Start the demo client pointing at your proxy:
   ```sh
   cd demo && PROXY_URL=https://idap.yourdomain.com go run .
   ```
2. Open `http://localhost:9090` and click **Sign In with IDAP**
3. On your phone, the app receives the auth request via WebSocket
4. Tap **Approve** — the demo client gets a signed JWT with your public key as the subject

#### Exchange contacts

1. Run the app on both a device and the simulator (or two devices)
2. On one: tap the add contact button, go to **Share** tab to show your QR code
3. On the other: scan the QR code
4. Both sides now have each other's public keys and can verify each other's identity

## Repository Layout

```
idap/
├── packages/
│   ├── idap-crypto/        Cryptographic primitives (Ed25519, AES-GCM, X25519, Shamir, BIP-39)
│   ├── idap-identity/      Persona management, credential wallet, W3C VCs
│   ├── idap-auth/          OIDC auth flow, JWT signing, WebSocket sessions
│   ├── idap-contacts/      Contact exchange, capability negotiation, encrypted contact book
│   └── idap-recovery/      Recovery map, shard encryption, seed reconstruction
├── proxy/                  Go server — key directory, inbox, OIDC provider, shard storage
├── demo/                   OIDC relying party demo — test client for the auth flow
├── ios/                    SwiftUI iOS reference app
└── docs/
    ├── protocol.md         Protocol specification
    ├── philosophy.md       Design philosophy — why the protocol is unopinionated
    ├── compromises.md      Pragmatic bridges and what could replace them
    ├── proxy.md            Proxy reference implementation
    ├── ios.md              iOS reference client implementation
    ├── demo.md             OIDC demo relying party
    ├── threat-model.md     Threat model — what's protected, what's not
    ├── use-cases.md        Real-world use cases
    ├── open-questions.md   Open questions seeking community input
    ├── backlog.md          What still needs to be built
    └── archive/
        ├── idap-spec.md    Original monolith spec (preserved for reference)
        └── decisions.md    Original architecture decisions (superseded by proxy.md + ios.md)
```

## Documentation

| Document | What's in it |
|----------|-------------|
| [Protocol Specification](docs/protocol.md) | Wire formats, endpoints, message structures — what any conforming implementation must do |
| [Philosophy](docs/philosophy.md) | Why the protocol is unopinionated, the spectrum of control, composition over invention |
| [Pragmatic Compromises](docs/compromises.md) | What's a bridge today and what could replace it |
| [Threat Model](docs/threat-model.md) | What IDAP protects, what it doesn't, known attack vectors |
| [Use Cases](docs/use-cases.md) | Self-hosted auth, passwordless login, portable identity, ZK age verification |
| [Open Questions](docs/open-questions.md) | Things we don't know yet — community input welcome |
| [Backlog](docs/backlog.md) | Everything not yet built, grouped by category |

### Implementation Docs

| Document | What's in it |
|----------|-------------|
| [Proxy](docs/proxy.md) | Go proxy — why Go, why SQLite, what it can/can't see, how to run it |
| [iOS App](docs/ios.md) | Reference client — why Swift, key derivation, recovery, app architecture |
| [Demo](docs/demo.md) | OIDC relying party test client — how to try the auth flow |

Each package and the iOS app have their own README with API details:
[idap-crypto](packages/idap-crypto/README.md) ·
[idap-identity](packages/idap-identity/README.md) ·
[idap-auth](packages/idap-auth/README.md) ·
[idap-contacts](packages/idap-contacts/README.md) ·
[idap-recovery](packages/idap-recovery/README.md) ·
[proxy](proxy/README.md) ·
[iOS app](ios/README.md)

## Contributing

This project is in its early stages and actively seeking feedback on:

- **Protocol design** — Is the spec sound? What's missing? Start with the [protocol spec](docs/protocol.md).
- **Security review** — The primitives are standard. The novelty is in their composition. Please break it.
- **Use cases** — What would you build on this? See [use cases](docs/use-cases.md).
- **Open questions** — See [open questions](docs/open-questions.md).
- **Philosophy** — Does the [design philosophy](docs/philosophy.md) hold up? Where does it break down?
