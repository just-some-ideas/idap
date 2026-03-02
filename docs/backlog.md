# Backlog

What still needs to be built and researched. Grouped by category, roughly prioritized within each.

---

## Protocol

- [ ] Inbox access codes (generation, validation, single-use enforcement — see [protocol](protocol.md#72-inbox-access))
- [ ] Access proof mechanism (signed grants, bearer tokens, or ZK proofs — see [protocol](protocol.md#73-access-proofs))
- [ ] Capability negotiation (request/grant/deny/revoke message types — see [protocol](protocol.md#74-capability-negotiation))
- [ ] Inbox routing (opaque routing context in grants, endpoint-internal routing — see [protocol](protocol.md#76-routing))
- [ ] Verifiable log implementation (format, hosting, verification — see [protocol](protocol.md#8-verifiable-log))
- [ ] Behavioral attestation (authorities certify senders follow declared messaging contracts)
- [ ] Per-key endpoint discovery (how clients resolve a key's capability URLs)
- [ ] Attestation-based inbox filtering (whitelist authorities, trust model)
- [ ] Scope negotiation (interactive vs declarative, attestation scopes)
- [ ] Two-part message implementation (header + payload, separate fetch)
- [ ] Key rotation via verifiable log (migration entries, contact notification)
- [ ] Key transparency (detect endpoint key substitution attacks)
- [ ] ZK proof system (credential issuance, proof generation, verification)
- [ ] Trust policy enforcement (co-signature rules, threshold schemes)

---

## Research

- [ ] Per-key verifiable log — explore existing transparency log implementations (Certificate Transparency, Key Transparency, Sigstore, Trillian). Key questions: hosting model, subscription/following, log format standards, lightweight verification for mobile. Private attestations via content ID (hash in public log, actual attestation presented directly).
- [ ] Trust policies in logs — can a key define rules like "revocation requires co-signature from key X"? Explore multi-sig and threshold signature schemes for policy enforcement.
- [ ] Two-part message format precedents — how Signal, Matrix, MLS, or other protocols handle header + payload separation and selective fetch.
- [ ] Encryption strategy for known vs unknown sender payloads — shared secret vs ephemeral key agreement vs direct public key encryption.
- [ ] Per-key endpoint discovery — how to resolve a key's individual capability URLs when they may be hosted at different locations. Consider: endpoint map in key bundle, per-key discovery URL, DNS-based resolution.
- [ ] OIDC provider trust model — proxy signs JWT (current direction). How do services verify the proxy's authority? Should there be attestation of trusted providers?
- [ ] Service identity via OIDC — `client_id` could be a service's public key, `client_secret` a signed nonce proving possession. Proxy verifies the signature (no pre-registration needed). App-side: trusted service lists built from attestations, so the user sees verified service identity during auth approval. Keeps plain-string client_id as a fallback for simple setups.
- [ ] Optional client registration on proxy — self-hosters may want to restrict which services can request auth from their proxy. Allowlist of `client_id` + `redirect_uri` pairs. Open by default, lockdown optional.
- [ ] Dynamic proxy selection during OIDC login — the authorize page lets the user specify their own proxy URL instead of assuming the service's proxy is the user's proxy. Enables real federation: any user, any proxy, any service. Service-side: a pre-OIDC step that accepts the user's proxy URL (or a `user@proxy` identifier resolved via `.well-known`), then starts the standard OIDC flow against that issuer. Client libraries don't need to change — the issuer URL is just dynamic input rather than static config.
- [ ] Attestation-based whitelist providers — how services get attested as non-abusive for inbox access, who runs the whitelist authorities, governance model.
- [ ] ZK proof for inbox access — can a sender prove set membership (authorized by inbox owner) without revealing which grant they hold? Explore ZK set membership proofs, group signatures, anonymous credentials.
- [ ] Access proof unlinkability — can successive deliveries from the same sender be unlinkable at the endpoint? Rotating proofs, blind signatures, ZK approaches.
- [ ] Confirmatory (private query) attestation patterns — how to verify a claim without publishing it (existing ZK or private set intersection approaches).
- [ ] Infrastructure alternatives for current compromises — IPv6/DHT for discovery, decentralized messaging for inbox, direct key-based auth standards beyond WebAuthn for OIDC bridge.

---

## Multi-Platform Libraries

- [ ] Kotlin client library (Android)
- [ ] TypeScript client library (web / Node)
- [ ] Rust client library
- [ ] Python client library
- [ ] Go server-auth library (verify key-based challenge-response)
- [ ] Node server-auth library
- [ ] Python server-auth library

---

## Proxy

- [ ] Inbox access code endpoint (`POST /inbox/{pubkey}/access-code`)
- [ ] Access code validation on inbox delivery (`access_code` field)
- [ ] Access proof validation on inbox delivery (`access_proof` field)
- [ ] Unverified delivery queue (optional, separate from verified inbox)
- [ ] Inbox redirect on key migration
- [ ] Two-part inbox (header + payload storage and separate fetch endpoints)
- [ ] Verifiable log endpoint (`/log/{pubkey}`)
- [ ] Proxy-signed JWT (provider JWKS, token issuance after user proof)
- [ ] Polling endpoint for auth requests (superseded by WebSocket at `/ws` for now)
- [ ] PostgreSQL support (alternative to SQLite for larger deployments)
- [ ] Rate limiting (per-IP and per-key)
- [ ] Federation testing (two proxies discovering and routing cross-proxy)
- [ ] Per-key endpoint support in key bundles
- [ ] Docker image
- [ ] Health check enhancements (DB connectivity, version info)
- [ ] Inbox message expiry (TTL-based cleanup)

---

## iOS App

- [ ] UI tests with real proxy (end-to-end flows, currently mocked)
- [ ] Passkey integration (WebAuthn registration after first IDAP login)
- [ ] Two-part message handling (header-first fetch, selective payload download)
- [ ] Scope UI (show requested scopes during auth, approve/deny)
- [ ] Multi-device sync (key registry + contacts via CloudKit)
- [ ] Push notification handling (real APNs delivery, background wake)
- [ ] Access code generation UI (generate and share inbox access codes)
- [ ] Capability request review UI (approve/deny/partial grant incoming requests)
- [ ] Inbox routing configuration (direct different senders to different inboxes)
- [ ] Deep link handling (idap:// URLs for contact adds and service invites)
- [ ] Credential wallet UI (store and present attestation credentials)
- [ ] Field sharing management UI (granular per-contact field control)

---

## Infrastructure

- [ ] CI/CD pipeline (run all tests on push)
- [ ] Automated cross-package testing (Swift + Go in one pipeline)
- [ ] Deployment tooling (proxy binary release, systemd unit generation)
- [ ] Docker Compose dev environment (proxy + demo relying party)
- [ ] Integration test suite (Swift client against real proxy)

---

## Documentation

- [ ] API reference generation (from proxy handler code)
- [ ] Integration guide for relying parties ("Add IDAP login to your service")
- [ ] Integration guide for self-hosted services ("Key-based auth in 30 minutes")
- [ ] Security audit preparation document
- [ ] Protocol versioning strategy
- [ ] Recommendations section (expert-contributed guidance on crypto choices, OIDC configuration, deployment security)

---

## Community

- [x] License decision (Apache 2.0)
- [ ] Contribution guidelines (CONTRIBUTING.md)
- [ ] Code of conduct
- [ ] Issue templates
- [ ] Security disclosure policy (SECURITY.md)
