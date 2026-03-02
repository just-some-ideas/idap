# Architecture Decisions

This document records the significant technical decisions in IDAP, why they were made, and what was considered.

---

## Public Keys as Identity (No Handles)

**Decision:** A persona's Ed25519 public key is its sole network identifier. There are no usernames, handles, or human-readable addresses in the protocol.

**Context:** The protocol needs a way to address personas. Traditional identity systems use human-readable names (email addresses, usernames, handles like `@alice@server.com`).

**Options considered:**
- Human-readable handles with DNS-based resolution (like email: `@alice@proxy.com`)
- Public keys as identifiers (shared via deep links, QR codes)
- DIDs (Decentralized Identifiers)

**Why this:** Handles create a namespace that must be managed — registration, uniqueness, squatting, migration. They also create a layer of indirection that adds complexity without adding security (the handle still resolves to a public key). Using the public key directly eliminates all of this. The key *is* the identity. URLs use `{base64url-pubkey}` in the path. The `sub` claim in JWTs is the base64 public key. The database primary key is the public key. No resolution step, no DNS, no WebFinger.

Users share their identity via deep links (`idap://add?key=...&proxy=...`) or QR codes, which encode the public key and proxy URL together.

**Tradeoffs:** Public keys are not human-readable. Users can't tell each other "I'm @alice" — they share a link or scan a QR code instead. Display names exist as optional cosmetic metadata (stored locally), but the network identifier is always the raw key. This is a deliberate choice: human-readable names invite all the problems of namespace management that IDAP is designed to avoid.

---

## Ed25519 for Signing, X25519 for Key Agreement

**Decision:** Use Ed25519 as the primary signing algorithm and X25519 for key agreement.

**Context:** The protocol needs digital signatures (identity, auth, records) and key agreement (contact exchange, shard encryption). P-256 is the only curve available in hardware security modules like Apple's Secure Enclave.

**Options considered:**
- Ed25519 + X25519 (Curve25519 family)
- P-256 everywhere (NIST curve, Secure Enclave compatible)
- Hybrid — Ed25519 for signing, P-256 for hardware-backed operations

**Why this:** Ed25519 has better performance, simpler implementation, no nonce misuse risk, and is the de facto standard in modern identity systems (SSH, Signal, age). X25519 is the natural pairing for key agreement on the same curve. P-256 is available as a secondary option for hardware-backed key derivation where Secure Enclave support is needed.

**Tradeoffs:** Ed25519 keys cannot be stored in the Secure Enclave on iOS — only P-256 keys can. This means persona signing keys are derived in software. The Secure Enclave is used to protect the master seed blob, not individual persona keys.

---

## BIP-32/BIP-39 for Key Derivation

**Decision:** Use BIP-39 for mnemonic encoding and SLIP-0010 (hardened BIP-32) for deterministic persona key derivation.

**Context:** Users need multiple independent key pairs (personas) derived from a single master seed, with optional mnemonic backup.

**Options considered:**
- BIP-32/BIP-39 (Bitcoin standard, well-audited)
- HKDF with manual index tracking
- Separate random keys per persona

**Why this:** BIP-39 gives us an interoperable 24-word mnemonic format that users and wallets already understand. SLIP-0010 extends BIP-32 to Ed25519, giving deterministic derivation with hardened paths (no public key leakage). Any implementation that supports these standards can derive the same keys from the same seed.

**Tradeoffs:** BIP-32 was designed for Bitcoin hierarchical wallets — we use a flat m/index' path which is simpler but doesn't leverage the hierarchy. The derivation is heavier than raw HKDF, but this runs at most once per app session.

---

## Login Codes (App-Initiated Auth)

**Decision:** Authentication is app-initiated. The user generates a short-lived login code in the app; the service uses it to route the request.

**Context:** Traditional OIDC flows let any relying party initiate an auth request against a known identity. This creates notification fatigue and enables phishing.

**Options considered:**
- Standard OIDC (service initiates, identity in URL)
- Login codes (app initiates, service uses code)
- QR-only (scan to start)

**Why this:** Login codes completely eliminate unsolicited auth requests. A service cannot cold-start a request — it needs a code the user deliberately generated from an authenticated session. The user controls when and where they authenticate. Codes are short-lived (5 minutes), single-use, and the service never learns the user's public key until after approval.

**Tradeoffs:** Extra step for the user (open app, generate code). This is an intentional friction point — it ensures the user is present and consenting. After the first login, passkey registration eliminates this for returning visits.

---

## Personas as Unlinkable Identities

**Decision:** Personas are fully independent identities, not sub-accounts. They share no externally detectable relationship.

**Context:** Users need multiple identities (work, gaming, personal) that cannot be correlated by services or proxies.

**Options considered:**
- Sub-accounts under a master identity (like email aliases)
- Fully independent personas derived from the same seed
- Separate accounts entirely (no shared seed)

**Why this:** Sub-accounts are linkable by design. Separate accounts require separate recovery. Derived-but-unlinkable personas give the best of both: one seed to back up, one recovery process, but each persona is cryptographically independent to observers. The derivation is private; the resulting keys share no mathematical relationship that is externally detectable.

**Tradeoffs:** The proxy can correlate personas by IP address and timing if they're registered at the same proxy. Mitigation: use different proxies per persona when separation is critical.

---

## Proxy as Dumb Pipe

**Decision:** The proxy stores only opaque encrypted blobs. It routes messages and serves public keys but cannot read content.

**Context:** A proxy operator should have minimal access to user data, even if compromised.

**Options considered:**
- Full-featured server (decrypts, indexes, searches)
- Dumb pipe (encrypted blobs only)
- Peer-to-peer (no server)

**Why this:** End-to-end encryption makes the proxy operator's trust requirements minimal: availability and routing, not confidentiality. A compromised proxy reveals timing metadata but no content. This also makes self-hosting safe — a self-hosted proxy with poor security practices still can't leak what it can't read.

**Tradeoffs:** No server-side search, no server-side contact matching, no push notification content. All processing happens on-device. This is intentional.

---

## Shamir Secret Sharing for Recovery

**Decision:** Split the master seed using k-of-n Shamir Secret Sharing across trusted contacts and a password-encrypted shard on the proxy.

**Context:** Users need to recover their identity if they lose their device. Recovery must not depend on a single point of failure.

**Options considered:**
- iCloud/Google backup only
- Social recovery (Shamir shards with contacts)
- Recovery phrase only (24 words)
- Hardware key backup

**Why this:** All of the above — as layered recovery paths. Shamir is the core mechanism because it distributes trust. No single contact, cloud provider, or backup medium can reconstruct the seed alone. The recovery map (who holds what) is stored in the user's own cloud — it contains no key material, just metadata.

**Tradeoffs:** Social recovery requires contacts to be available and cooperative. The timed-code mechanism (verbal, 15-minute, one-time) adds friction to prevent remote attacks. For users with no IDAP contacts, cloud backup + recovery phrase are the fallback paths.

---

## SQLite for the Proxy

**Decision:** SQLite as the primary database for the proxy server.

**Context:** The proxy needs persistent storage for users, inbox messages, shards, and OIDC sessions.

**Options considered:**
- SQLite (embedded, zero-config)
- PostgreSQL (full RDBMS)
- Key-value store (Redis, BadgerDB)

**Why this:** SQLite is a single file, requires no separate daemon, and handles the proxy's workload easily. Self-hosters can run the proxy as a single binary with no database infrastructure. For higher-scale hosted deployments, PostgreSQL support is planned as an option.

**Tradeoffs:** SQLite's write concurrency is limited to one writer at a time. For a proxy serving hundreds of users, this is fine. For thousands of concurrent writers, PostgreSQL would be needed.

---

## Go for the Proxy

**Decision:** Go as the implementation language for the proxy server.

**Context:** The proxy needs to be a single deployable binary that self-hosters can run easily.

**Options considered:**
- Go (static binary, good stdlib, easy deployment)
- Node.js (widespread, easy to hire for)
- Rust (performance, safety)

**Why this:** Go compiles to a single static binary with no runtime dependencies. `go build` produces something you can `scp` to a server and run. The stdlib includes a production-quality HTTP server, WebSocket support is mature (gorilla/websocket), and SQLite has a stable cgo binding. The language is simple enough that anyone can read and audit the proxy code.

**Tradeoffs:** Go's error handling is verbose. CGO is required for SQLite (via `go-sqlite3`), which complicates cross-compilation. A pure-Go SQLite driver exists but is less mature.

---

## Swift-First Client Libraries

**Decision:** Build client libraries in Swift first, targeting iOS as the reference implementation.

**Context:** The protocol needs at least one complete client implementation to validate the design.

**Options considered:**
- TypeScript first (widest reach)
- Kotlin first (Android)
- Swift first (iOS)
- Multi-platform from day one

**Why this:** iOS has the most complete platform crypto story (CryptoKit, Secure Enclave, Keychain, APNs, AuthenticationServices) which means fewer third-party dependencies and a more auditable implementation. The resulting app is the highest-fidelity expression of the protocol. Kotlin, TypeScript, Rust, and Python implementations are planned.

**Tradeoffs:** iOS-first means Android users can't participate yet. This is a prototype validation, not a product launch.

---

## X3DH for Contact Exchange

**Decision:** Use Extended Triple Diffie-Hellman (X3DH) for establishing shared secrets between contacts.

**Context:** Contacts need to establish an encrypted channel through an asynchronous medium (inbox).

**Options considered:**
- Simple Diffie-Hellman (both parties online)
- X3DH (asynchronous, forward secrecy)
- Pre-shared keys

**Why this:** X3DH is designed exactly for this: asynchronous key agreement where the initiator can establish a shared secret using the recipient's pre-published key bundle, without the recipient being online. One-time pre-keys provide forward secrecy per contact exchange. The protocol is proven in Signal and well-understood.

**Tradeoffs:** Key bundle management (publishing and consuming one-time pre-keys) adds complexity. Pre-key exhaustion needs handling.

---

## W3C VC-Compatible Credential Format

**Decision:** Use a credential format compatible with W3C Verifiable Credentials.

**Context:** IDAP needs a signed credential format for attestations (age, identity, professional status).

**Options considered:**
- Custom format
- W3C Verifiable Credentials
- JWT-only claims

**Why this:** W3C VCs are an emerging standard with broad ecosystem support. Using a compatible format means IDAP credentials can interoperate with other VC systems. The format is JSON, human-readable, and extensible.

**Tradeoffs:** The full W3C VC spec is complex. IDAP uses a compatible subset — enough for interoperability without the full machinery.

---

## Single Monolith Proxy

**Decision:** The proxy is a single binary that serves key directory, OIDC provider, inbox, and shard storage.

**Context:** These could be separate services or a single unified server.

**Options considered:**
- Microservices (separate key server, auth server, inbox, shard store)
- Monolith (single binary, all endpoints)

**Why this:** For self-hosters, one binary is one thing to deploy. Conceptually these are distinct concerns; practically they share a database and a deploy target. Splitting later is straightforward if needed — the HTTP endpoints are already cleanly separated.

**Tradeoffs:** All-or-nothing deployment. A self-hoster who only wants key directory still gets inbox and OIDC. The overhead is minimal.

---

## iCloud/Google Drive for Recovery Map

**Decision:** Store the recovery map (who holds which shard) in the user's own cloud storage, not on the proxy.

**Context:** The recovery map tells you who to contact when recovering. It needs to survive device loss.

**Options considered:**
- On the proxy
- In user's own cloud (iCloud/Google Drive)
- On a separate backup service

**Why this:** The recovery map contains no key material — just public keys and shard IDs. Storing it in plaintext in the user's own cloud means recovering it requires only their Apple ID or Google account (which they need anyway for a new device). Storing it on the proxy would add a dependency on the proxy being available during recovery and would require the proxy to store user metadata it shouldn't need.

**Tradeoffs:** Depends on Apple/Google cloud availability. If both the proxy and cloud are unavailable, the user still has the recovery phrase as last resort.

---

## No In-App PIN

**Decision:** No IDAP-specific PIN or password for daily app unlock. Device security handles authentication entirely.

**Context:** The app needs to gate access to the master seed.

**Options considered:**
- In-app numeric PIN
- In-app password
- Device security only (Secure Enclave + biometric/passcode)

**Why this:** A 6-digit numeric PIN checked in software is crackable offline in under a second. The Secure Enclave-protected device passcode cannot be attacked offline at all — hardware enforces retry limits (10 attempts then wipe) and the key never leaves the hardware. Adding a software PIN on top of hardware security is strictly weaker, not stronger. The only user-created password is the recovery passphrase for cloud backup, used only during recovery on a new device.

**Tradeoffs:** Users without a device passcode must set one during onboarding. This is a feature — it ensures every IDAP user has hardware-backed security.
