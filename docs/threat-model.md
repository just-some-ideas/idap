# Threat Model

What IDAP protects, what it doesn't, known attack vectors, and mitigations. For protocol design philosophy, see [Philosophy](philosophy.md). For implementation-specific security choices, see [iOS](ios.md) and [Proxy](proxy.md).

---

## What IDAP Protects

| Threat | Protection |
|--------|-----------|
| Service stores your PII | Services receive only `sub` (public key) by default. PII sharing is explicit, per-field, via [scopes](protocol.md#56-scopes). |
| Endpoint reads your messages | Inbox messages are encrypted client-side. The endpoint stores opaque blobs ([two-part header + payload](protocol.md#71-message-format)). |
| Unsolicited inbox messages | Inbox delivery requires an [access code or proof](protocol.md#72-inbox-access). The inbox owner controls who can reach them via [capability negotiation](protocol.md#74-capability-negotiation). |
| Auth request phishing | Number-match requires visual verification. [Login codes](protocol.md#51-login-code-generation) prevent unsolicited requests. |
| Auth assertion tampering | JWTs are [signed by the OIDC provider](protocol.md#55-jwt-format). The user proves identity to the provider via key signature — the chain is verifiable end-to-end. |
| Fraudulent attestations | Claims are verified against the authority's [verifiable log](protocol.md#8-verifiable-log). Tampered or revoked attestations break the chain. |

---

## What IDAP Does Not Protect

### Endpoint Operator Correlation

If multiple keys are served by the same endpoint, the operator can correlate them by IP address and timing. This is operational, not cryptographic — the endpoint has no mathematical link between keys.

**Mitigation:** Use different endpoints per key for sensitive separations. [Per-key endpoints](protocol.md#47-per-key-endpoints) allow mixing providers per capability.

### IP-Level and Network Correlation

A network observer (ISP, VPN provider) can see that a device communicates with specific endpoints. Timing analysis is possible for well-resourced adversaries. No protocol-level mitigation exists for this — it's outside the protocol's scope. Users who need network-level privacy can use existing tools (VPN, Tor) independently.

### Push Notification Metadata

If an implementation uses push notifications (APNs, FCM), Apple/Google can observe device token, timestamp, and app ID. Payload content is encrypted in transit, but the existence and timing of events is visible metadata.

**Mitigation:** Push is not required by the protocol. The core auth flow uses [WebSocket during active login and polling otherwise](protocol.md#53-auth-request-delivery). Push is an implementation-level UX enhancement, not a protocol dependency.

### Endpoint Operator Abuse

A malicious endpoint operator can:
- Drop messages or deny service to specific public keys
- Observe which services a user logs into (from OIDC `client_id`)
- See inbox message delivery timing (not content)
- Attempt to serve stale or incorrect key bundles

A malicious endpoint operator cannot:
- Read encrypted message payloads or headers
- Forge authentication — JWTs are signed by the provider, but the user's identity proof is cryptographically verifiable
- Link keys served by different endpoints

**Mitigation:** Self-hosting eliminates the trusted-operator requirement. The protocol minimizes what the operator learns by design. [Verifiable logs](protocol.md#8-verifiable-log) provide tamper-evident records. Key transparency ([planned](backlog.md)) would allow clients to detect key substitution.

---

## Abuse Vectors

### Inbox Spam

Without access control, any sender could deliver messages to any inbox.

**Mitigation:** [Access-controlled inbox](protocol.md#72-inbox-access). Delivery requires an access code (for initial contact) or access proof (for ongoing delivery). The inbox owner generates single-use codes and controls who can reach them. Within [capability negotiation](protocol.md#74-capability-negotiation), senders include attestation references — recipients verify these before granting ongoing access. See [Spam Prevention](protocol.md#79-spam-prevention).

### Sybil Attacks

At endpoints that accept registration, nothing in the protocol prevents bulk key registration.

**Planned mitigation:** Proof of work on registration (endpoint policy, not protocol requirement). Expiry for inactive registrations. These are endpoint-level decisions — different endpoints can set different policies.

---

## Trust Hierarchy

```
User's device         — Source of truth. Holds keys. Performs signing.
Endpoint operator     — Trusted for availability and routing. Cannot read content.
                        Can observe: key existence, service names (OIDC),
                        message timing.
                        Cannot observe: message content, key linkage
                        across endpoints.
OIDC provider         — Signs JWTs. Trusted to issue tokens only after
                        verifying the user's key signature. Services verify
                        tokens against the provider's JWKS.
Relying party         — Trusted only after explicit user approval.
                        Receives: sub claim, approved scopes only.
                        Never receives: other keys, PII not explicitly shared.
Attestation authority — Trusted for the claims it makes. Verifiable via
                        public log. Different authorities trusted by different
                        services — no universal trust root.
Network / ISP         — Untrusted. Sees: which endpoints you connect to, timing.
                        Does not see: content (TLS), which keys are yours.
```

---

## Implementation Status

This table reflects the [reference implementation](ios.md) (iOS app + [Go proxy](proxy.md)).

| Protection | Status |
|-----------|--------|
| Client-side encryption (inbox, contacts) | Implemented |
| Signed auth assertions | Implemented |
| Number-match auth flow | Implemented |
| Login code (app-initiated auth) | Implemented |
| Inbox access codes and proofs | Not yet implemented |
| Capability negotiation | Not yet implemented |
| Attestation-based inbox filtering | Not yet implemented |
| Verifiable log | Not yet implemented |
| Per-key endpoints | Not yet implemented |
| PoW registration (proxy policy) | Not yet implemented |
| ID expiry/pruning (proxy policy) | Not yet implemented |
| Key transparency | Not yet implemented |
| ZK proof attestations | Not yet implemented |

---

> This project is seeking security review. The [reference implementation](ios.md) uses well-established primitives (Ed25519, X25519, AES-256-GCM). The novelty is in the protocol layer that composes them. [Please break it.](open-questions.md)
