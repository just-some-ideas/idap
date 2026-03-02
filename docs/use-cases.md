# Use Cases

Concrete scenarios where IDAP solves real problems. The protocol is [unopinionated](philosophy.md) — these examples show how different implementations might use it, not how it must be used.

---

## Self-Hosted Service Auth

**The problem:** You run a game server, private wiki, or Teamspeak for friends. Today that means managing per-user passwords, dealing with password resets, or trusting a third-party OAuth provider.

**With IDAP:** You share an invite link. Your friend opens it in an IDAP app, and their public key is registered on your server. Authentication is [direct key-based](protocol.md#6-direct-key-based-authentication) — challenge-response, no passwords, no accounts, no proxy needed on the server side. The server stores a table of authorized public keys and verifies signatures. That's it.

Invite links create organic onboarding — every self-hosted service becomes an onboarding channel for the broader ecosystem.

---

## Passwordless Login for Websites

**The problem:** "Login with Google" gives Google visibility into everywhere you authenticate. Username/password means another credential to manage and another breach surface.

**With IDAP:** A "Login with IDAP" button on any website. The user opens the app, generates a [login code](protocol.md#51-login-code-generation), enters it on the website. Number-match confirmation, done. The service receives a `sub` claim and nothing else — no name, no email, no PII unless the user explicitly shares it via [scopes](protocol.md#56-scopes). After the first login, a passkey can be registered for instant future access.

---

## Portable Identity

**The problem:** Your identity lives on a platform. Delete your Google account and you lose access to every service you signed into with it. Your reputation, your credentials, your contact graph — all platform-dependent.

**With IDAP:** Your identity is a key pair. You can change endpoints (like changing email providers) without losing your identity — publish a [migration record](protocol.md#84-migration) and contacts update automatically. No platform can revoke your identity because no platform issued it.

---

## Privacy-Preserving Age Verification

**The problem:** "Are you over 18?" means handing over your birthdate (or worse, a photo of your ID) to every service that asks. That data gets stored, breached, and traded.

**With IDAP:** Get an age credential once from a trusted authority. The authority adds it to their [verifiable log](protocol.md#8-verifiable-log) and deletes the PII. Present a [zero-knowledge proof](protocol.md#89-zero-knowledge-proofs) to any service: "age >= 18" with zero additional information. No birthdate shared, no ID photo, no linkage between presentations. Services can request this via the `attestation:age_gte_18` [scope](protocol.md#56-scopes).

---

## Professional Credentials

**The problem:** Proving you're a licensed doctor, a credentialed journalist, or a bar-certified lawyer means carrying physical documents or relying on centralized databases that services must individually integrate with.

**With IDAP:** Your professional body issues a signed [attestation](protocol.md#88-credential-format-w3c-vc-compatible) to your public key. Present it anywhere — any service that trusts the issuing authority accepts it immediately. The credential is verifiable against the authority's [log](protocol.md#8-verifiable-log). No re-verification per service. The credential travels with you, not with the authority's database.

---

## Developer Identity

**The problem:** Your commit history lives on GitHub. Your packages live on npm. Your code reviews live on GitLab. None of them are connected. If you leave a platform, your attribution history stays behind.

**With IDAP:** One key for development. Git commits signed with your key are verifiable across any forge. Package authentication, code review attribution, security advisory authorship — all tied to one portable key. Move platforms, keep your verified history.

---

## Community Moderation / Web of Trust

**The problem:** Moderating online communities means trusting a platform's identity system (easily gamed) or building custom reputation systems from scratch.

**With IDAP:** Contacts form a web of trust. A community can require an introduction from an existing member — "someone I already trust vouches for you." Combined with authority attestations (verified human, age gate), this creates layered trust without a central authority. New members earn trust through connections, not through a platform's opaque algorithm.

---

## Selective Disclosure

**The problem:** Every service you sign up for collects and stores your personal information. You don't control what they keep, how long they keep it, or who they share it with.

**With IDAP:** Services receive only what you explicitly share via [scopes and contact cards](protocol.md#74-contact-cards), per-field, per-service. Revoke a field with a [field_revoke message](protocol.md#73-well-known-message-types). The default is zero PII — services that don't need your name don't get your name.

---

## Organizational Identity

**The problem:** Businesses need to issue and revoke employee credentials, control access to internal services, and maintain audit trails. Current solutions require vendor lock-in to identity providers like Okta or Azure AD.

**With IDAP:** The organization is an [attestation authority](protocol.md#87-authority-discovery). It issues credentials to employee keys, controls revocation via its [verifiable log](protocol.md#8-verifiable-log), and can set [trust policies](protocol.md#85-trust-policies) (e.g., "revocation requires HR co-signature"). Employees authenticate to internal and external services using their keys. The organization gets full control; employees get a portable identity that works beyond the org boundary if the org allows it.
