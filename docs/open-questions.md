# Open Questions

Things we don't know yet. Community input welcome. See also the research items in the [Backlog](backlog.md).

---

## Verifiable Log

**Log hosting and replication.** Where does a key's [verifiable log](protocol.md#8-verifiable-log) live? Options: authority-hosted, proxy-hosted, replicated across multiple endpoints, decentralized storage. What's the right balance of availability, cost, and decentralization? Existing transparency log implementations (Certificate Transparency, Key Transparency, Sigstore, Trillian) may provide models.

**Log discovery and subscription.** How does a client follow a key's log for updates? Polling the log endpoint? A pub/sub mechanism? What's lightweight enough for mobile clients?

**Private attestation verification at scale.** [Private attestations](protocol.md#83-public-and-private-attestations) use a content ID in the public log. For high-volume authorities (millions of attestations), is linear log scanning practical? Should the log support indexed lookups by content ID?

**Trust policy enforcement.** Can [trust policies](protocol.md#85-trust-policies) like "revocation requires co-signature from key X" be enforced by the log host, or only verified by clients? What happens if a log host accepts an entry that violates a policy?

---

## Messaging

**Two-part message encryption.** The [header + payload model](protocol.md#71-message-format) requires both parts to be encrypted. For known contacts (established shared secret), symmetric encryption is fast. For unknown senders (no shared secret), what's the right approach? Ephemeral key agreement? Direct public key encryption? How do existing protocols (Signal, Matrix, MLS) handle this?

**Message type extensibility.** [Well-known message types](protocol.md#73-well-known-message-types) and custom types via reverse-domain — is this the right extensibility model? Should there be a registry, or is convention sufficient?

**Field revocation delivery.** If a contact is offline when a [field revocation](protocol.md#73-well-known-message-types) is sent, the inbox holds the message. How long should revocations be retained? Should the app re-send on reconnect?

---

## Discovery and Endpoints

**Per-key endpoint discovery.** [Per-key endpoints](protocol.md#47-per-key-endpoints) allow a key's capabilities to live at different URLs. How does a client discover a key's endpoint map? Options: embedded in the key bundle, a per-key discovery URL, DNS-based resolution. How does this affect the addressing scheme?

**Federation at scale.** With per-key endpoints, any capability could live anywhere. How do clients efficiently resolve endpoints for keys they haven't seen before? Is caching sufficient, or do we need a more structured discovery layer?

---

## Authentication

**Proxy as JWT signer.** The OIDC provider [signs JWTs](protocol.md#55-jwt-format), not the user. This is standard OIDC, but it means services must trust the provider. What's the trust model for OIDC providers? Should there be an attestation mechanism for trusted providers? How does a service decide which providers it accepts?

**Scope negotiation.** [Scopes](protocol.md#56-scopes) let services request attestations and contact info. Should scope negotiation be interactive (the user sees what's requested and negotiates) or declarative (the service states requirements, the user meets them or doesn't)?

**Direct key-based auth standard.** [Direct key-based auth](protocol.md#6-direct-key-based-authentication) is currently loosely specified. Should the protocol define a stricter challenge-response format, or leave it flexible for implementors?

---

## Security

**Attestation trust governance.** How should the ecosystem address an authority issuing fraudulent credentials? Revoke the authority's key in their log? Who decides? Is there a governance process, or is it purely market-driven (services stop trusting them)?

**Attestation-based spam prevention.** [Whitelist authorities](protocol.md#75-spam-prevention) attest non-abusive services for inbox access. Who runs these authorities? What's the governance model? How do new services get attested?

**Metadata minimization.** Should endpoints log sender information at all, or route messages blind (knowing only the recipient)? Blind routing removes abuse investigation capability but improves privacy.

**PoW difficulty.** For endpoints using proof-of-work registration — what difficulty target at launch? Fixed, epoch-based adjustment, or endpoint-configured?

---

## UX

**Login code format.** Short typed code vs QR-only vs deep link — what's the right primary UX for desktop-to-phone login initiation? Current design uses typed code + QR. Is that sufficient?

**Multi-device.** What state needs syncing between devices? How are conflicts resolved? Should the protocol define anything about multi-device, or is it purely implementation?

---

## Cryptography

**ZK proof library.** noir vs circom/snarkjs — which has the better mobile story? ZK proofs need to run on-device in 1-3 seconds. Library maturity, proof size, and verifier performance all matter.

**Algorithm evolution.** The protocol defines a [supported algorithm set](protocol.md#2-signing-algorithms). What's the process for adding or deprecating algorithms? How do existing keys migrate when an algorithm is deprecated?

---

## Web of Trust

**Expanding trust without exposing keys.** How can a contact introduction happen without the introducer revealing their own key to the new party? Is transitive trust desirable, or should every trust relationship be direct?
