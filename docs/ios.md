# iOS App — Reference Implementation

The iOS app is the reference client implementation. It's the first complete expression of the protocol — identity creation, OIDC authentication, contact exchange, and recovery all working end-to-end.

This document describes the implementation — why these choices were made and how the app is structured. For the protocol-level specification, see [Protocol Specification](protocol.md).

---

## Why Swift / iOS First

iOS has the most complete platform crypto story — CryptoKit, Secure Enclave, Keychain, APNs, AuthenticationServices — which means fewer third-party dependencies and a more auditable implementation. The resulting app is the highest-fidelity test of the protocol.

**Tradeoffs:** iOS-first means Android users can't participate yet. Kotlin, TypeScript, Rust, and Python implementations are [planned](backlog.md). This is a prototype validation, not a product launch.

---

## Personas — Multiple Identities from One Seed

The app implements a "persona" model — multiple independent identities derived from a single master seed. Each persona is a separate key pair with its own contacts, credentials, and signed records. From the outside, personas share no detectable relationship.

This lets a user maintain separate identities for different contexts (work, personal, gaming) without managing separate accounts or recovery processes. One seed to back up, one recovery flow, but each persona is cryptographically independent to observers.

The app supports two identity modes per persona:

- **Persistent** — same key everywhere. Any two services can confirm it's the same identity. Good for: developer identity, professional credentials, public figures.
- **Pairwise** — per-service derived key. Two services receive different keys and cannot link the user. Good for: pseudonymous or privacy-focused use.

**This is an implementation pattern, not a protocol concept.** The protocol sees only individual public keys. It has no concept of a "persona," a "master account," or a relationship between keys. Other implementations could use a single key, generate random keys, or organize keys in a completely different way.

---

## Key Derivation — BIP-32 / BIP-39

The app uses BIP-39 for mnemonic encoding (24-word backup phrase) and SLIP-0010 (hardened BIP-32) for deterministic persona key derivation from a master seed.

BIP-39 gives an interoperable mnemonic format that users and wallets already understand. SLIP-0010 extends BIP-32 to Ed25519, giving deterministic derivation with hardened paths (no public key leakage). Any implementation that supports these standards can derive the same keys from the same seed.

**Tradeoffs:** BIP-32 was designed for Bitcoin hierarchical wallets — the app uses a flat `m/index'` path which is simpler but doesn't leverage the hierarchy. The derivation is heavier than raw HKDF, but runs at most once per app session.

**This is an implementation choice, not a protocol requirement.** The protocol doesn't specify how keys are derived. Other implementations could use HKDF, random generation, hardware keys, or any other method.

---

## Signing — Ed25519

Ed25519 is the signing algorithm used in the reference implementation. It has better performance than P-256, simpler implementation, no nonce misuse risk, and is the de facto standard in modern identity systems (SSH, Signal, age). X25519 is the natural pairing for key agreement on the same curve.

**Tradeoffs:** Ed25519 keys cannot be stored in the Secure Enclave on iOS — only P-256 keys can. Persona signing keys are derived in software. The Secure Enclave is used to protect the master seed blob, not individual persona keys.

**This is an implementation choice.** The protocol defines supported signing algorithms; it doesn't mandate Ed25519.

---

## Contact Exchange — X3DH

Contact exchange uses Extended Triple Diffie-Hellman (X3DH) for establishing shared secrets between contacts. X3DH is designed for asynchronous key agreement — the initiator establishes a shared secret using the recipient's pre-published key bundle without the recipient being online. One-time pre-keys provide forward secrecy per contact exchange. The protocol is proven in Signal and well-understood.

**Tradeoffs:** Key bundle management (publishing and consuming one-time pre-keys) adds complexity. Pre-key exhaustion needs handling.

---

## Recovery — Shamir Secret Sharing

The app splits the master seed using k-of-n Shamir Secret Sharing across trusted contacts and a password-encrypted shard on the proxy. No single holder can reconstruct the seed alone.

Recovery paths (in order of convenience):
1. **Contact codes** — timed codes from k contacts + recovery password
2. **Old device** — transfer code from existing device
3. **Hardware key** — tap key + recovery password
4. **Recovery phrase** — 24 BIP-39 words (last resort)

The recovery map (who holds which shard) is stored locally on-device. It contains no key material — just public keys and shard IDs.

**Tradeoffs:** Social recovery requires contacts to be available and cooperative. The timed-code mechanism (verbal, 15-minute, one-time) adds friction intentionally — to prevent remote attacks. For users with no IDAP contacts, the recovery phrase is the fallback.

**This is entirely an implementation choice.** The protocol defines revocation and migration — how others discover that a key is no longer valid or has moved. It does not define how you recover your own keys. Other implementations could use different backup strategies entirely.

---

## Device Security

The app uses Secure Enclave for seed protection and device biometrics (Face ID / Touch ID) for unlock. There is no in-app PIN or password — the Secure Enclave hardware enforces retry limits and the key never leaves the hardware, which is strictly stronger than any software-checked credential.

The only user-created password is the recovery passphrase, used only during recovery on a new device.

---

## Architecture

The app is built with SwiftUI. Key architectural patterns:

- **`IDAPSession`** is the app-wide state hub (`ObservableObject`), created in `AppDelegate`, injected via `@EnvironmentObject`
- **Protocol conformances** in `Protocols/Conformances.swift` adapt the Swift packages (`IDAPIdentity`, `IDAPAuth`, `IDAPContacts`, `IDAPRecovery`) to app-level protocols
- **`DatabaseManager.shared`** provides file-backed GRDB queues for production
- Views that create `@StateObject` ViewModels accept session as an init parameter

---

## Building

```sh
cd ios && xcodegen generate && open IDAP.xcodeproj
# Cmd+U to run unit tests
# Cmd+R to run (requires proxy running for full flows)
```

## Source Layout

```
ios/
├── IDAP/
│   ├── App/              AppDelegate, session setup
│   ├── Views/            SwiftUI views
│   ├── ViewModels/       View models
│   ├── Protocols/        Protocol conformances bridging packages to app
│   ├── Services/         Networking, database
│   └── Models/           App-level models
├── IDAPTests/            Unit tests (self-contained, no proxy needed)
└── project.yml           xcodegen spec
```
