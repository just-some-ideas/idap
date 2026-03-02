# Philosophy

IDAP is a protocol. Like HTTP or SMTP, it defines how things communicate — not what they communicate about, not who uses them, not why.

The protocol specifies how cryptographic identities are discovered, authenticated, attested, and how revocations are published. It does not have opinions about how those capabilities are used. A privacy-maximalist app and a fully transparent enterprise directory can both speak IDAP, the same way a bank and a blog both speak HTTPS.

Good protocols last because they stay simple, stay consistent, and don't care how you use them. That's what we're trying to build.

---

## Not Anonymity — Choice

IDAP is not an anonymity project. It is not a privacy project. It is an identity protocol that supports a spectrum from full transparency to full pseudonymity, and lets users, applications, and organizations decide where they sit on that spectrum.

A government agency publishing public servant identities for accountability? Valid use of IDAP. A whistleblower using an unlinkable persona to contact a journalist? Also valid. The protocol doesn't prefer one over the other. The applications built on top make those choices — the protocol just makes sure the choices are possible.

Anonymity is not a goal because true anonymity at the protocol level is probably not achievable — network-level observation, metadata correlation, and infrastructure dependencies all leak information. What the protocol *can* do is avoid creating unnecessary linkage and give implementations the tools to minimize exposure when that's what their users want.

---

## The Spectrum of Control

Different users need different tradeoffs between convenience, security, and autonomy. The protocol doesn't pick a point on this spectrum — it defines the building blocks, and implementations compose them however they want.

Some examples of where implementations might sit:

**Casual user.** Sets a master password. Keys are generated and managed by the app. Recovery shards are distributed to contacts automatically. The proxy handles OIDC. It feels like signing up for any other service — except the user's identity is portable and not owned by the service provider.

**Self-hoster.** Runs their own proxy. Uses OIDC bridges for compatibility with existing services but handles direct key-based auth where possible. Accepts the operational cost because they want to minimize trust in third parties.

**Organization.** Issues employee identities under an organizational authority. Full control over attestation and revocation. Employees get the convenience of managed keys; the organization gets the control it needs.

The protocol doesn't know or care which of these is happening, or where any of these keys came from. It defines how attestations are verified, how revocations are discovered, and how messages are exchanged. Everything else — key generation, storage, derivation, registration, backup — is an implementation decision.

A key doesn't need to be registered anywhere for the protocol to work. Attestations verify against the key itself, not against a directory entry. Registration is an application concern — a proxy might require it to know which keys it should hold messages for, and the reference app defaults to registering with a main proxy for OIDC convenience, but none of that is protocol.

---

## Composition, Not Invention

IDAP does not invent new cryptographic primitives, new credential formats, or new transport protocols. It composes existing, proven standards:

- **Credentials:** W3C Verifiable Credentials — an emerging standard with broad ecosystem support
- **Auth compatibility:** OpenID Connect — the auth protocol every web service already speaks
- **Signing:** EdDSA (Ed25519) — the same algorithm used in SSH, Signal, and age
- **Key agreement:** X25519 and X3DH — proven in Signal
- **Encryption:** AES-256-GCM — NIST standard, hardware-accelerated on every modern device

The novelty is in how these pieces fit together, not in the pieces themselves. The protocol specifies interfaces — a supported signing algorithm, a credential format, an auth flow — rather than mandating specific implementations. The cryptographic suite can evolve. When better primitives emerge, the protocol can adopt them without breaking the architecture — the same way TLS added new cipher suites over time without redesigning the handshake.

The [reference implementation](decisions.md) makes specific choices within these interfaces (BIP-32 for key derivation, Shamir for recovery, SQLite for storage), but those are implementation decisions, not protocol requirements.

---

## Pragmatic Compromises

Some parts of the current design exist because the infrastructure we'd prefer doesn't exist yet — or exists but isn't widely deployed. These are [bridges](compromises.md), not destinations.

**OIDC as auth bridge.** The protocol includes an OIDC-compatible auth flow because that's what web services speak today. Direct key-based authentication is simpler and more secure, but it requires services to integrate a new auth method. OIDC compatibility lets IDAP work with existing services immediately while the ecosystem grows.

**Proxy as discovery and routing.** Ideally, identities could be discovered and messages routed without a central intermediary. In practice, most devices don't have stable public addresses — IPv6 adoption would change this, but we're not there yet. The proxy fills this gap as a minimal, replaceable intermediary.

Each of these compromises is designed to be replaceable. The protocol doesn't depend on OIDC or proxies conceptually — it depends on discovery and authentication. Today's implementations fill those roles with what's available. Tomorrow's can swap them out.

See [Pragmatic Compromises](compromises.md) for a deeper discussion of each bridge, what infrastructure gap it fills, and what could replace it.

---

## Passkeys

Passkeys are good. IDAP uses them. After a first login via the OIDC flow, a passkey is registered silently for instant future access. This is the right UX for returning authentication — no code, no number-match, just biometric confirm.

But passkeys solve authentication, not identity. A passkey proves you control a credential registered at a specific service. It doesn't give you portable identity, attestable credentials, or selective disclosure. Your passkeys live in iCloud Keychain, or Google Password Manager, or 1Password — the credential is better than a password, but the lock-in pattern is the same.

IDAP operates at a layer below passkeys. The protocol defines identity, discovery, attestation, and messaging. Passkeys are one mechanism for authenticating that identity to a specific service after the initial exchange. They're complementary, not competing.

---

## What Success Looks Like

IDAP succeeds if it becomes unnecessary. The protocol exists because the internet's identity primitives haven't arrived yet — there's no standard, open, unopinionated way to do key-based identity, discovery, attestation, and messaging. If those primitives emerge natively, IDAP should get out of the way.

In the meantime, success looks like the protocol being simple and unopinionated enough that different apps, services, and organizations adopt it for different reasons — the same way different organizations all use HTTP without agreeing on anything else. The measure isn't how many people use an IDAP app. It's whether the protocol is boring enough to be infrastructure.
