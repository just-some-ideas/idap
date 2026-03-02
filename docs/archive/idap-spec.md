# IDAP
## Identity & Attestation Protocol — Technical Specification
*Prototype Design v0.1*

---

> **Core Concept**
>
> Identity provider + contacts app = web of trust.
>
> Public keys have always been the right foundation for identity. The missing piece was always distribution: sharing them easily, discovering them reliably, and building trust around them without a central authority. IDAP solves that. Your contacts *are* your web of trust — key exchange is the point, not a side effect. Everything else follows from that primitive.

---

## Table of Contents

1. [Overview](#1-overview)
   - 1.2 [Persona Separation Model](#12-persona-separation-model)
   - 1.3 [What IDAP Replaces](#13-what-idap-replaces)
   - 1.4 [Self-Hosted as the Adoption Wedge](#14-self-hosted-as-the-adoption-wedge)
2. [System Components](#2-system-components)
   - 2.1 [idap-crypto](#21-idap-crypto--library)
   - 2.2 [idap-identity](#22-idap-identity--library)
   - 2.3 [idap-contacts](#23-idap-contacts--library)
   - 2.4 [idap-proxy](#24-idap-proxy--server)
   - 2.5 [idap-auth](#25-idap-auth--library)
   - 2.6 [idap-recovery](#26-idap-recovery--library)
   - 2.7 [idap-attestation](#27-idap-attestation--library--server)
3. [Mobile App](#3-mobile-app)
4. [Prototype Build Order](#4-prototype-build-order)
5. [Tech Stack Summary](#5-tech-stack-summary)
6. [Open Questions for Community Review](#6-open-questions-for-community-review)
7. [Threat Model](#7-threat-model)

---

## 1. Overview

IDAP is an open identity protocol built on three simple primitives:

| Component | What It Is | What It Does |
|---|---|---|
| **App** | iOS/Android native app | Holds your keys, manages personas, approves auth requests, contacts book |
| **Proxy** | Lightweight Go server | Handle-to-key DNS, message routing, encrypted blob storage, OIDC provider |
| **Protocol** | Open spec | Federation, key discovery, credential format, recovery flows |

Everything sensitive lives on the user's device. The proxy is a dumb pipe — it routes messages and serves public keys but cannot read anything it stores. There is no central authority. Anyone can run a proxy. Proxies federate automatically via a simple discovery protocol.

### 1.2 Persona Separation Model

**Personas are externally unlinkable identities, not sub-accounts.**

Each persona is a completely independent identity to the outside world:

- Separate key pair derived from the master seed — the derivation is private, the keys share no mathematical relationship that is externally detectable
- Separate handle at the proxy (or a different proxy entirely)
- Separate contact list — contacts of one persona have no knowledge of other personas
- Separate credentials and signed records
- The proxy treats each persona as an unrelated stranger — it has no concept of a "master account"
- No persona is publicly linked to any other, nor to the master seed

The master seed is a local secret that never touches the network. It exists solely to allow the user to derive and recover their persona keys. From the outside, there is no "IDAP account" — there are only personas, each a fully independent cryptographic identity.

**The first persona created during onboarding is the user's "real me" identity** — their primary, real-world self. Additional personas (gaming, work, journalist, streamer, etc.) are added later and are completely detached, sharing nothing visible with the primary persona or with each other.

### 1.3 What IDAP Replaces

| Today | With IDAP |
|---|---|
| Username + password per service | One key, works everywhere |
| OAuth via Google / Apple / Facebook | OAuth via your own identity |
| PII stored on every service | Services store zero PII by default |
| Account recovery via email | Recovery via contacts you trust |
| Service lock-in | Portable — change proxy, keep identity |
| Bots / fake accounts | Web of trust limits sybil attacks |
| Per-service user management for self-hosted | Invite link → public key → done |
| "Are you over 18?" → collect birthdate | ZK proof: age ≥ 18, zero PII |
| Trust delegated to Google / Apple / Facebook | Trust delegated to any authority you choose |

### 1.4 Self-Hosted as the Adoption Wedge

Self-hosters are the natural early-adopter community for IDAP. They already run their own infrastructure, already understand public keys, and are already frustrated with managing per-service accounts for the people they share access with. A Teamspeak admin dealing with password resets for five friends has a solved problem the moment those friends have the IDAP app.

**Invite links create organic onboarding.** When a self-hoster shares an IDAP access invite, the recipient needs the app to accept it. That's natural, frictionless onboarding that benefits the broader ecosystem — the self-hoster is doing the work without thinking about it.

**The server side is just a public key.** Adding IDAP auth to any self-hosted service means storing a `(handle → public_key)` table and verifying Ed25519 signatures. No proxy, no OAuth server, no account database. A minimal server library for this — one function to verify a signed challenge, available in Go, Node, Python, Rust — is a first-class deliverable.

**What people build on top is up to them.** An access portal, a multi-service dashboard, a bot, an admin UI — all of these are just applications of the same primitive: a public key you can share easily, backed by a web of trust. The protocol doesn't need to spec those out. It needs to make the primitive solid so the ecosystem can.

---

## 2. System Components

---

### 2.1 idap-crypto  (Library)

> **Language:** Swift (iOS) | Kotlin (Android) | TypeScript (web/Node)
> **Purpose:** All cryptographic primitives. No network, no storage. Pure functions.
> **Dependencies:** None beyond platform crypto (CryptoKit / Android Keystore / SubtleCrypto)

This is the foundation everything else builds on. It must be auditable, minimal, and have no side effects.

#### API Surface

```ts
// Key generation
generateMasterSeed() → Uint8Array[32]           // random 256-bit seed
seedToMnemonic(seed) → string[24]               // BIP-39 encoding
mnemonicToSeed(words) → Uint8Array[32]          // BIP-39 decoding

// Persona key derivation (BIP-32 hardened)
derivePersonaKey(seed, index) → KeyPair         // m/index' Ed25519
derivePersonaKeyP256(seed, index) → KeyPair     // m/index' P-256 (Secure Enclave compatible)

// Signing & verification
sign(privateKey, message) → Signature
verify(publicKey, message, signature) → bool

// Key agreement
generateEphemeralX25519() → KeyPair
deriveSharedSecret(myPrivate, theirPublic) → Uint8Array
hkdf(secret, salt, info, length) → Uint8Array

// Symmetric encryption
encrypt(key, plaintext) → { ciphertext, nonce, tag }  // AES-256-GCM
decrypt(key, ciphertext, nonce, tag) → plaintext

// Shamir secret sharing
splitSecret(secret, k, n) → Share[]            // k-of-n
reconstructSecret(shares: Share[]) → Uint8Array

// Secure Enclave (iOS/Android specific)
generateEnclaveKey(label) → PublicKey           // key never leaves hardware
enclaveEncrypt(enclaveKeyLabel, data) → Uint8Array
enclaveDecrypt(enclaveKeyLabel, ciphertext) → Uint8Array
// biometric auth required — OS handles prompt
```

#### Key Storage Model

```
On device:
  Secure Enclave key (hardware)  →  created with kSecAccessControlUserPresence
                                    (biometrics OR device passcode, hardware-enforced)
                                    The SE refuses to operate without user auth —
                                    this cannot be bypassed in software
  Master seed blob               →  AES-256-GCM encrypted with SE key
                                    stored in Keychain, kSecAttrAccessibleWhenUnlockedThisDeviceOnly
  Persona keys                   →  never stored, derived on demand from seed
                                    cleared from memory immediately after use

On unlock:
  Keychain item access triggers OS auth prompt (Face ID → Touch ID → device passcode)
  SE decrypts seed blob → seed held in memory until app backgrounds or locks
  No in-app PIN entry involved — device security handles authentication entirely
  Device passcode is itself protected by SE: hardware retry limits, 10 attempts → wipe

In iCloud / Google Drive (user's own account):
  encryptedSeedBlob = AES-256-GCM(masterSeed, backupKey)
  backupKey         = Argon2id(recoveryPassword, deviceSalt, mem=64MB, iter=3)
  recoveryPassword  = alphanumeric passphrase chosen during onboarding
                      not a PIN — no length or character restrictions
                      used only on new-device recovery, not for daily unlock
  No plaintext seed ever leaves device
```

> **Note on "in-app PIN":** An in-app numeric PIN is not used for daily unlock. The device passcode (which users already have) combined with Secure Enclave access control is strictly stronger — hardware brute-force protection, not software. A 6-digit numeric PIN checked in software is crackable offline in under a second. The SE-protected device passcode cannot be attacked offline at all: the SE enforces delays and a 10-attempt wipe, and the key never leaves the hardware. The only password the user creates during onboarding is the recovery password for the iCloud backup, which should be a passphrase, not a short PIN.

---

### 2.2 idap-identity  (Library)

> **Language:** Swift / Kotlin / TypeScript
> **Purpose:** Persona management, credential wallet, signed record format.
> **Depends on:** idap-crypto

#### Persona Model

```ts
interface Persona {
  id: string                    // 'real' | 'gaming' | 'work' | custom
  derivationIndex: number       // BIP-32 index m/n'
  publicKey: Uint8Array         // Ed25519 or P-256
  proxy: string                 // 'https://idap.app' or self-hosted URL
  fallbackProxy?: string
  reliability: 'critical' | 'best_effort' | 'relaxed'
  keySource: 'secure_enclave' | 'software' | 'hardware_key'
  handle: string                // '@alice@idap.app'
  identityMode: 'persistent' | 'pairwise'  // see Identity Modes below
  publicProfile?: PersonaProfile
}

interface PersonaProfile {
  displayName?: string          // optional, user controlled
  avatar?: string               // hash of image, not the image itself
  bio?: string
  // all fields optional — default persona exposes nothing
}
```

#### Identity Modes

Each persona has an `identityMode` that controls how it presents itself to services. This is a per-persona choice, not a protocol requirement. Apps may set different defaults or expose the choice to the user.

**`persistent` — same key everywhere**

The persona's public key is the same across all services. JWT tokens embed the raw persona public key. Any two services that receive a token from this persona can confirm it's the same key.

This is a feature, not a flaw, for personas where consistent public attribution is the point:
- Developer identity: git commits, package signatures, code reviews all tied to one key across any forge or registry. Builds a verifiable, portable, platform-independent reputation.
- Purchases and licenses: receipts signed to your persona key are verifiable by any service. Ownership is portable — the key is the owner, not a platform account.
- Professional credentials: attestations issued to your key (press credential, licence, certification) are presentable anywhere without re-verification.
- Public figures: a journalist, researcher, or artist who wants their work to be consistently attributable across platforms.

**`pairwise` — per-service derived key**

A unique keypair is derived for each service: `serviceKey = deriveHardened(personaKey, hash(client_id))`. The JWT embeds the service-specific public key. Two services receive different keys and cannot link the user by key comparison.

The `sub` claim is also pairwise (`HMAC(personaKey, "idap.ppid:" + client_id)`), so there is no stable cross-service identifier in the token at any layer.

Best for personas where unlinkability across services is the priority: pseudonymous identities, personas for sensitive contexts, privacy-focused use.

**Tradeoffs**

| | Persistent | Pairwise |
|---|---|---|
| Cross-service correlation | Possible (by design) | Not possible |
| Attestations | Simple — issued once to key, verifiable anywhere | Complex — ZK proof required to decouple key from credential |
| Signed artifacts (commits, records) | Consistent, attributable history | Per-service, not portable |
| Token verification | Self-contained, no proxy needed | Self-contained, no proxy needed |
| Proxy JWKS confirmation | `GET /jwks/{handle}` | `GET /jwks/{handle}?client_id={id}` |

Note: attestations using ZK proofs (section 2.7) work in both modes — the proof attests to credential validity without exposing the underlying key. Where pairwise mode pays a complexity cost is in non-ZK contexts: direct credential presentation and signed records.

**The ecosystem implication**

Because this is a per-persona choice rather than a protocol mandate, different applications can make different decisions and coexist:
- A developer-focused app defaults to persistent, because verifiable commit history is the product
- A privacy-first app defaults to pairwise, because unlinkability is the product
- A general-purpose app exposes the choice during persona creation
- An enterprise app might enforce persistent for accountability

The protocol supports all of these. Apps express opinions; the primitive stays neutral.

#### API Surface

```ts
// Persona lifecycle
createPersona(seed, opts) → Persona
listPersonas() → Persona[]
getPersonaKey(persona, seed) → KeyPair          // derives on demand, clears after use
getServiceKey(persona, seed, clientId) → KeyPair // pairwise derived key for a specific service

// Credential wallet
storeCredential(persona, credential) → void
listCredentials(persona) → Credential[]
getCredential(persona, type) → Credential | null

// Signed records (purchases, licenses, attestations)
verifyRecord(record) → { valid: bool, issuer: string, subject: string }
signRecord(persona, seed, record) → SignedRecord

// Proof generation
proveAgeOver(credential, minAge, today) → ZKProof
proveHuman(credential) → ZKProof
proveOwnership(record, nonce) → OwnershipProof
```

#### Derivation Index Registry

Persona keys are derived deterministically via SLIP-0010: `derivePersonaKey(seed, index)` at path `m/index'`. Because derivation is deterministic, reusing an index after a persona is deleted would produce the same key for a different persona — a security violation.

The **derivation registry** is a permanent, append-only table that tracks every index ever allocated:

```sql
CREATE TABLE derivation_registry (
    idx INTEGER PRIMARY KEY,   -- the derivation index, never reused
    nickname TEXT               -- optional human-readable label
);
```

**Allocation rule:** `nextDerivationIndex()` returns `MAX(idx) + 1` from the registry (or 0 if empty). When a persona is created, a row is inserted into the registry atomically in the same transaction. When a persona is deleted, its registry row is **not** removed — the index remains permanently claimed.

**Nicknames** are stored alongside indices so that a future restore flow can present a human-readable list of previously-used personas. They are updated independently via `updateRegistryNickname(index, nickname)`.

**Future: Restore flow (not yet implemented)**
1. Recover seed from recovery phrase
2. Fetch registry from cloud backup (CloudKit / user's sync mechanism)
3. Browse indices and nicknames to select which personas to restore
4. Re-derive keys from seed + index
5. Re-register public keys at proxy

**Future: Multi-device sync (not yet implemented)**
The registry is the minimal state that needs syncing alongside the recovery map (section 2.6). It contains no key material — only indices and nicknames. Conflict resolution: union of indices (an index claimed on any device is claimed everywhere); nickname conflicts resolved by last-write-wins timestamp.

#### Signed Record Format  (W3C Verifiable Credential compatible)

```json
{
  "type": ["VerifiableCredential", "PurchaseRecord"],
  "issuer": "did:idap:steam_store",
  "issuedTo": "did:idap:persona:x7f3k9m2",
  "issuanceDate": "2026-02-26",
  "credentialSubject": {
    "item": "Half-Life 3",
    "licenseType": "perpetual",
    "transactionId": "tx_abc123"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "steam_store#signing-key",
    "signature": "z5a3b..."
  }
}
```

---

### 2.3 idap-contacts  (Library)

> **Language:** Swift / Kotlin / TypeScript
> **Purpose:** Encrypted contact exchange, PII storage, local contact book.
> **Depends on:** idap-crypto, idap-identity

All PII lives locally on the device or in the user's own encrypted cloud backup. The proxy never sees contact details.

#### Contact Exchange Protocol  (X3DH)

```
// Alice adds Bob

1. Alice fetches Bob's public key bundle from his proxy
   GET https://bob-proxy.com/.well-known/idap/keys/@bob

2. X3DH key agreement
   sharedSecret = X3DH(alice.identityKey, bob.identityKey,
                        bob.signedPreKey, bob.oneTimePreKey)

3. Alice encrypts her contact card
   encryptedCard = AES-256-GCM(alice.contactCard, sharedSecret)

4. Alice sends to Bob's proxy inbox
   POST https://bob-proxy.com/inbox/@bob
   { from: alice.handle, payload: encryptedCard }

5. Bob's app decrypts locally, stores contact
   Bob can choose to share his card back (same flow reversed)

Background (automatic, silent):
   Alice's app generates a Shamir shard of her master seed
   Encrypts shard with Bob's public key
   Stores at Bob's proxy inbox
   Updates Alice's recovery map
```

#### API Surface

```ts
// Contact management
initiateContact(myPersona, seed, theirHandle) → PendingContact
acceptContact(myPersona, seed, pendingContact) → Contact
listContacts(persona) → Contact[]
getContact(persona, handle) → Contact | null
removeContact(persona, handle) → void

// PII sharing
shareField(contact, field, value, persona, seed) → void
revokeField(contact, field) → void

// Recovery shard management (runs automatically in background)
distributeShard(shard, contact, myPersona, seed) → void
requestShard(contact, myPersona) → ShardRequest
generateRecoveryCode(requestingContact) → TimedCode  // 15 min TTL
redeemRecoveryCode(code, password) → Shard
```

#### Key-Based Access for Self-Hosted Services

A common use case for people who self-host: giving friends access to a Teamspeak server, game server, private wiki, etc. Today this means sharing passwords or managing per-user accounts. With IDAP, the server owner shares an invite link; the friend's app registers their persona's public key on the server; the server uses that key for all future authentication. No accounts, no passwords, no IDAP proxy required on the server side.

```
Setup (server owner does once):
  Configure server to accept IDAP key-based auth
  Server exposes an auth endpoint: POST /idap-auth/register  (accepts a public key)
  Server exposes a challenge endpoint: GET /idap-auth/challenge

Granting access (owner → friend):
  Owner shares an invite URL:
    idap://access?name=My+Teamspeak&endpoint=https://ts.example.com/idap-auth&token=<invite_token>
  invite_token is single-use, short-lived (owner generates it in server admin UI)

Friend accepts (in IDAP app):
  App parses the invite URL
  User selects which persona to use for this service
  App POSTs persona public key + invite token to the server's register endpoint
  Server validates token (single-use), adds public key to its allowed list
  Server optionally returns a list of field names it would like (display_name, avatar)
  User reviews and approves which fields to share (standard field schema — see below)
  App stores this service in contacts with type: 'service'

Authentication (all future connections):
  Server: GET /idap-auth/challenge → { nonce, expires_at }
  App: signs { nonce, service_endpoint, timestamp } with persona private key
  App: POST /idap-auth/verify { handle, signature, nonce }
  Server: looks up public key by handle, verifies Ed25519 signature → granted

Revoking access:
  Owner removes the public key from server's allowed list
  User can also "remove contact" in app — sends a revocation notice to the server endpoint
```

The server needs no IDAP proxy, no OAuth library, and no account database. The only requirements are: store a `(handle → public_key)` table, issue nonces, and verify Ed25519 signatures. Client libraries for this will be straightforward to implement in any language.

Field sharing in this context lets the server display the user's chosen display name or avatar — the user explicitly approves what the server sees, can update it later, and can revoke it when they leave.

#### What the Ecosystem Can Build

Because the server-side requirement is just a public key and a challenge-response, anything can sit on top of it. An access portal, a multi-service dashboard, a bot that manages invites, a web UI for a private community — all of these are just web applications that verify Ed25519 signatures and use IDAP for their own auth. None of them require new protocol features. They're applications of the primitive.

The spec doesn't define what those applications look like. It defines the primitive cleanly so they can be built reliably.

#### Standard Field Schema

Fields shared between contacts use a pre-defined schema. Custom fields are allowed but interoperability requires using standard names. Clients should display known fields with friendly labels; unknown fields are shown as raw key-value pairs.

```ts
// Standard field names (all optional, all user-controlled)
interface ContactFields {
  // Identity
  display_name?:   string   // "Alice"
  given_name?:     string   // "Alice"
  family_name?:    string   // "Smith"
  pronouns?:       string   // "she/her"
  avatar_url?:     string   // URL to image (hash in key bundle, image elsewhere)
  bio?:            string

  // Contact info
  email?:          string
  phone?:          string   // E.164 format
  website?:        string

  // Location
  city?:           string
  country?:        string   // ISO 3166-1 alpha-2

  // Social handles (plain usernames, not URLs)
  github?:         string
  twitter?:        string
  mastodon?:       string   // e.g. "@alice@mastodon.social"

  // Verified facts (backed by attestation credentials — see section 2.7)
  age_verified?:   boolean  // true = holds a valid L3+ age credential
  human_verified?: boolean  // true = holds a valid L4+ human credential
  country_verified?: string // ISO code, backed by L5 credential

  // Dates
  birthday?:       string   // ISO 8601, e.g. "1990-04-15". Share with caution.

  // Custom fields — arbitrary key-value, displayed as-is
  [key: string]:   string | boolean | undefined
}
```

Field sharing is always explicit and per-contact. Defaults to sharing nothing. Revoking a field sends a revocation message to the contact's inbox; the contact's app removes the field locally. The proxy never sees field values — they travel encrypted through the inbox.

#### Local Storage Schema

```sql
-- contacts.db  (SQLite, encrypted with Secure Enclave key)

CREATE TABLE contacts (
  handle       TEXT PRIMARY KEY,
  persona      TEXT,         -- which of my personas knows them
  contact_type TEXT,         -- 'person' | 'service'
                             -- person: mutual X3DH contact exchange
                             -- service: key registered at a self-hosted endpoint;
                             --          no X3DH, no inbox, no shard distribution
  publicKey    BLOB,         -- their public key (persons and services)
  sharedSecret BLOB,         -- X3DH derived (persons only)
  endpoint     TEXT,         -- auth endpoint URL (services only)
  holdsShardId TEXT,         -- if they hold a recovery shard for me (persons only)
  fields       JSON,         -- ContactFields they have shared with me (persons)
                             -- or field names the service requested (services)
  my_fields    JSON,         -- which of my fields I have shared with them
  addedAt      INTEGER
);

CREATE TABLE recovery_map (
  shardId          TEXT PRIMARY KEY,
  holderHandle     TEXT,
  holderType       TEXT,    -- 'contact' | 'proxy' | 'hardware_key' | 'cloud'
  encryptionMethod TEXT,    -- 'pubkey' | 'password' | 'hardware'
  kOfN             TEXT     -- '2-of-4'
);
```

---

### 2.4 idap-proxy  (Server)

> **Language:** Go
> **Purpose:** Handle-to-key DNS, message routing, OIDC provider, shard storage.
> **Deployment:** Single binary. SQLite for self-hosted. Postgres for hosted.
> **Self-hostable:** Yes — download binary, run it. No Docker required.

#### HTTP API

```
// Discovery (WebFinger + IDAP config)
GET  /.well-known/webfinger?resource=acct:alice@idap.app
GET  /.well-known/idap-configuration
GET  /.well-known/openid-configuration
GET  /jwks/@{username}                  // per-user public keys

// Key management
GET  /keys/@{username}                  // current public key bundle
PUT  /keys/@{username}                  // update key (signed by current key)
POST /keys/@{username}/revoke           // revoke key (signed by master key)

// Inbox / message routing
POST /inbox/@{username}                 // deliver encrypted message
GET  /inbox/@{username}                 // poll for messages (auth required)
DEL  /inbox/@{username}/{messageId}     // delete after processing

// Profile (optional static metadata)
GET  /profile/@{username}               // public persona profile
PUT  /profile/@{username}               // update (signed by persona key)

// Recovery (shards only — recovery map is never stored on the proxy)
POST /recovery/shard/@{username}        // store encrypted shard blob (opaque to proxy)
GET  /recovery/shard/@{username}/{id}   // retrieve shard (requires signed timed code)

// OIDC provider
POST /oidc/login-code                   // app registers a short-lived login code (auth required)
GET  /oidc/authorize                    // service initiates auth flow using a login code
GET  /oidc/ws                           // WebSocket — app receives and submits auth requests
POST /oidc/token                        // exchange code for token
GET  /oidc/userinfo                     // claims endpoint

// Migration
GET  /migration/@{username}             // signed migration record
POST /migration/@{username}             // publish migration notice
```

#### Federation Discovery

```
Handle: @alice@her-proxy.com

Step 1: Parse → username=alice, domain=her-proxy.com
Step 2: GET her-proxy.com/.well-known/idap-configuration

Response:
{
  "issuer": "https://her-proxy.com",
  "protocol_version": "1",
  "authorization_endpoint": "https://her-proxy.com/oidc/authorize",
  "jwks_uri": "https://her-proxy.com/jwks",
  "key_endpoint": "https://her-proxy.com/keys",
  "inbox_endpoint": "https://her-proxy.com/inbox",
  "recovery_endpoint": "https://her-proxy.com/recovery"
}

Step 3: All subsequent calls go directly to her-proxy.com
        Proxy never needed for verification — services resolve keys directly
        Works exactly like email MX records
```

#### Proxy as OIDC Provider

Auth is **app-initiated**. The user opens the app and generates a short-lived login code; the service uses that code to route the request. A service cannot cold-start an auth request against a persona — it needs a code the user deliberately generated. This eliminates unsolicited auth request flooding entirely.

```
Auth flow:

1. User opens app, selects persona, taps "Log in somewhere"
   → App: POST /oidc/login-code  (signed by persona key)
   → Proxy: generates short code, stores { code → handle, expires_in: 300s }
   → Proxy: returns { code: "7K3-M9X", expires_in: 300 }
   → App: displays code + QR for user to present to the service

2. User enters code on service (or service scans QR)
   → Service: GET /oidc/authorize?code=7K3-M9X&client_id=gamesite.com&redirect_uri=...
   → Proxy: looks up which persona handle owns this code
   → Proxy: delivers auth request to that persona's open WebSocket session
   → No handle in the authorize URL — service learns the identity only after approval

3. App receives auth request over WebSocket (already open — app generated the code)
   → No APNs push needed; app is live by definition
   → User sees: service name, persona being used, scopes requested
   → User taps correct number → Face ID confirms
   → App signs JWT assertion with persona key
   → Sends assertion to proxy over WebSocket

4. Proxy wraps in standard OIDC code response
   → Service calls /oidc/token to exchange
   → Service verifies JWT against /jwks/{handle}

Key properties:
  - No cold-call auth requests possible — code must come from an authenticated app session
  - Service never learns the handle until after approval (sub claim in token)
  - App is already open when the request arrives — WebSocket delivery guaranteed
  - APNs is a fallback enhancement only, not required for the core flow
  - Proxy is not in the trust chain — just a router
  - sub claim is pairwise — different per service (see below)
```

#### Token Signing and Subject Identifiers

How the JWT is signed and what `sub` contains depends on the persona's `identityMode`.

**Persistent mode**

```
sub  = persona handle  (e.g. "@alice@proxy.com")
jwk  = raw persona public key (embedded in JWT header)
kid  = fingerprint of persona public key

Verification: self-contained — relying party verifies signature with embedded key
Caching:      /jwks/{handle} for freshness confirmation; stable, rarely changes
```

**Pairwise mode**

```
signingKey  = deriveHardened(personaKey, hash(client_id))  // per-service keypair
sub         = base64url(HMAC-SHA256(personaKey, "idap.ppid:" + client_id))
jwk         = service-specific derived public key (embedded in JWT header)

Verification: self-contained — relying party verifies with embedded derived key
Caching:      /jwks/{handle}?client_id={id} for confirmation; stable per service
Unlinkable:   both sub and jwk are different for every service
```

In both modes the JWT is self-contained — no network call required to verify a token. The proxy JWKS endpoint is available for optional freshness confirmation (key rotation detection) but is not on the critical path.

The persona handle is never exposed in a pairwise token. In persistent mode the handle is the `sub`, which is intentional — persistent personas are meant to be consistently attributable.

#### Login Code Schema

```sql
-- Added to proxy database
CREATE TABLE login_codes (
    code       TEXT PRIMARY KEY,          -- short alphanumeric, e.g. "7K3M9X"
    handle     TEXT NOT NULL,             -- which persona registered this code
    expires_at INTEGER NOT NULL,          -- unix timestamp, typically now + 300s
    used       INTEGER NOT NULL DEFAULT 0 -- consumed on first authorize call
);
```

Code format: 6–8 uppercase alphanumeric characters, displayed as `XXX-XXX` for readability. QR encodes the full authorize URL: `https://{proxy}/oidc/authorize?code=XXXXXX&...`

#### Database Schema  (SQLite)

```sql
CREATE TABLE users         (handle, pubkey_bundle, profile_json, created_at);
CREATE TABLE inbox         (id, recipient, sender_hint, encrypted_blob, delivered_at);
CREATE TABLE shards        (id, handle, encrypted_blob, updated_at);
-- proxy stores shard blobs only; they are opaque encrypted bytes, proxy cannot read them
-- recovery map is never stored on the proxy — see section 2.6
CREATE TABLE login_codes   (code, handle, expires_at, used);
-- single-use codes generated by the app to initiate a login session
-- a service cannot start an auth request without a code the user generated
CREATE TABLE oidc_sessions (id, handle, service, nonce, number_match, expires_at, approved);
CREATE TABLE migrations    (handle, signed_record, published_at);
```

---

### 2.5 idap-auth  (Library)

> **Language:** Swift / Kotlin / TypeScript
> **Purpose:** OIDC client logic, passkey management, push notification handling.
> **Depends on:** idap-crypto, idap-identity

#### API Surface

```ts
// Inbound auth requests (from push notification payload)
parseAuthRequest(payload) → AuthRequest
approveAuthRequest(request, persona, seed) → SignedAssertion
denyAuthRequest(request) → void

// Passkey management (WebAuthn)
registerPasskey(service, persona, seed) → PasskeyCredential
// called silently after first IDAP login to a service
authenticatePasskey(service, challenge) → Assertion
// subsequent logins — no proxy needed, works offline

// Pre-authorization (skip push for trusted services)
createPreAuthorization(service, persona, seed, ttl) → PreAuth
// 'auto-approve this service for N days'
checkPreAuthorization(service, persona) → PreAuth | null

// PII request handling
parsePIIRequest(payload) → PIIRequest
approvePIIRequest(request, persona, fields) → EncryptedPII
denyPIIRequest(request) → void
```

#### Push Notification Payload

```json
{
  "type": "auth_request",
  "requestId": "uuid",
  "service": "gamesite.com",
  "serviceDisplayName": "GameSite",
  "personaHint": "gaming",
  "requesting": ["openid", "age_verified"],
  "numberMatch": 47,
  "nonce": "xyz789",
  "expiresAt": 1740000030,
  "locationHint": "London, UK"
}
```

```
APNs headers:
  apns-priority: 10                    // high priority, wakes device
  apns-push-type: alert
  apns-expiration: 30                  // matches auth timeout
  interruption-level: time-sensitive   // bypasses Focus modes
```

#### Session Tiers

| Tier | Trigger | Method | Proxy needed? |
|---|---|---|---|
| 1 — Passkey session | Normal usage | WebAuthn / Face ID | No — offline capable |
| 2 — IDAP re-auth | Sensitive operation | Push + number match | Yes |
| 3 — Full re-verify | New device / suspicious | Full IDAP flow + fresh ZK proof | Yes |

---

### 2.6 idap-recovery  (Library)

> **Language:** Swift / Kotlin / TypeScript
> **Purpose:** All recovery flows — shard distribution, reconstruction, key migration.
> **Depends on:** idap-crypto, idap-contacts

#### Recovery Map

```json
{
  "scheme": "2-of-4",
  "shards": [
    { "holder": "@bob@idap.app",   "method": "pubkey",   "shardId": "a3f9" },
    { "holder": "@carol@idap.app", "method": "pubkey",   "shardId": "b7c2" },
    { "holder": "@dave@idap.app",  "method": "pubkey",   "shardId": "c1e8" },
    { "holder": "proxy",            "method": "password", "shardId": "d4a1" }
  ]
}
```

> This document is **plaintext and contains no key material**. Safe to store anywhere. Finding it reveals nothing useful without also compromising 2 of the 4 shard holders.

**The recovery map is stored unencrypted in the user's own iCloud Drive / Google Drive private container — never on any proxy.** Because it contains no key material, encryption would only create a chicken-and-egg problem (you need the key to decrypt it, but you're recovering because you lost the key). Storing it in the user's own cloud means recovering it requires only an Apple ID or Google account login on the new device — which you need anyway to download the encrypted seed blob.

#### API Surface

```ts
// Setup
generateRecoveryMap(seed, contacts) → RecoveryMap
updateRecoveryMap(seed, contacts) → RecoveryMap    // called when contacts change
saveRecoveryMap(map) → void                        // writes plaintext to user's iCloud/Google Drive
fetchRecoveryMap() → RecoveryMap                   // reads from user's own cloud storage

// Shard distribution (automatic when contacts added)
createShardsForContacts(seed, contacts, k) → { shards, map }
encryptShardForContact(shard, contactPubKey) → EncryptedShard
encryptShardWithPassword(shard, password) → EncryptedShard

// Recovery code generation (contact opens app manually to help)
generateRecoveryCode(shardId, myPersonaKey) → TimedCode
// TimedCode: { code: '4X-7K2-9M', expiresAt, nonce, signature }
// Valid 15 minutes. One-time use. Requires verbal delivery.

// Recovery (on new device)
fetchRecoveryMap() → RecoveryMap                   // from user's own cloud — no key needed
redeemContactShard(timedCode, recoveryPassword) → Shard
redeemPasswordShard(proxy, shardId, recoveryPassword) → Shard
reconstructSeed(shards: Shard[]) → Uint8Array

// Key migration
createMigrationRecord(oldKey, newKey, newProxy) → SignedMigration
publishMigration(migration, oldProxy, newProxy) → void
```

#### Recovery Code Security

```
Format:   'R4-7K2-9M'  (base32 of truncated HMAC over shardId + timestamp + nonce)
Valid:    15 minutes
Use:      One-time (nonce tracked by proxy)
Delivery: Verbal only — UI explicitly says "read this to them directly, do not text"

Bob generates a code for Alice:
  code = base32(truncate(sign(shardId + timestamp + nonce, bob.key), 8 chars))

Alice enters code + recovery password on new device:
  Proxy verifies: bob's signature valid + not expired + nonce not seen before
  Proxy releases: encrypted shard blob
  Alice's app: decrypts shard with recovery password (separate factor)
  Still needs one more shard from any source

Attack resistance:
  No remote trigger — Bob opens app manually, no push notification
  Attacker needs: code (verbal, 15 min window) + Alice's password (separate factor)
  'This wasn't Alice' button — silently flags suspicious requests
```

#### Recovery Paths

| Path | What You Need | When To Use |
|---|---|---|
| A — Cloud backup | PIN / biometric on new device | Lost phone, have iCloud/Google backup |
| B — Contact code | Code from any 2 contacts + recovery password | Lost phone + cloud backup |
| C — Old device | Old device generates its own code + PIN | Have old device, getting new one |
| D — Hardware key | Tap hardware key + recovery password | Stored key in drawer/safe |
| E — Recovery phrase | 24 BIP-39 words | Everything else failed |
| F — Institutional | Canada Post / equivalent in-person | Nuclear option — loses persona history |

---

### 2.7 idap-attestation  (Library + Server)

> **Language:** Go (server) | TypeScript (verification library)
> **Purpose:** Issue and verify signed attestations. Fully pluggable — any authority.
> **Examples:** Age verification, press credentials, citizenship, professional licensing, community membership.

#### The Model: Externalised Trust

Peer contacts establish trust at the human level — "I know this person." Authorities establish trust at the institutional level — "this persona meets this verifiable standard." The two compose: a service can require both a trusted contact introduction *and* an age attestation, or either alone, depending on its needs.

Any entity can be an authority. A government body, a press accreditation association, an employer, a professional licensing board, a university, a community moderator — all of them are just entities with a public key that services choose to trust. The protocol doesn't define a hierarchy of authorities. Services decide which authorities they accept. New authorities can emerge without protocol changes.

The key properties that make this work:

- **The authority issues once and forgets.** After issuing a signed credential to a persona, the authority doesn't need to be involved when the persona presents it. No callback, no session, no tracking.
- **The credential travels with the persona, not the authority's database.** The persona holds it; the authority doesn't maintain a live registry of presentations.
- **ZK proofs decouple the claim from the underlying fact.** Proving "age ≥ 18" reveals nothing about the actual birthdate. Proving "is a journalist" reveals nothing about which outlet. The service gets the minimum it needs to make a decision.
- **The same credential works across any service that trusts the issuing authority.** No re-verification, no sharing PII with each service separately.
- **Different personas can hold the same credential.** A person's age credential issued to their master key can be presented from any persona — the ZK proof proves inclusion in the authority's tree without linking the personas to each other.

```
Examples of authority types:

Government:          Citizenship, age, driver's licence status, tax residency
Professional bodies: Press credential, medical licence, legal bar membership
Employers:           Staff status, clearance level, role
Platforms:           "Verified account on X", "Pro subscriber"
Communities:         "Member of this forum since 2019", "moderator"
Self-service:        Email control, phone control, payment on file (low trust)
```

#### Trust Levels

These levels describe the strength of verification behind a credential, not a single global hierarchy. A service might accept L2 for one decision and require L5 for another. A community might define its own levels.

| Level | Description |
|---|---|
| L0 — Self-attested | User claimed it. Unverified. |
| L1 — Email / phone | Controls that address. Low bar. |
| L2 — Payment verified | Has a real bank account. |
| L3 — Age gate | ID scan, 18+. Dedicated attestation provider. |
| L4 — Verified human | Biometric liveness, one-person-one-account. |
| L5 — Government ID | Passport / national ID, full identity verified. |

#### Authority API  (Any authority implements this)

An authority is an entity with a public key and two endpoints. That's the full interface. Authorities are discovered via their IDAP handle — they register at a proxy like any other persona.

```
// Authority server endpoints
POST /attest                // submit verification request, receive signed credential
GET  /revocation/tree       // current Merkle tree root (updated periodically)
GET  /ocsp/{credId}         // real-time revocation check (L5 only)
GET  /.well-known/attestation-configuration
     → { issuer, pubkey, supported_claims, revocation_interval }

// Client library — run on device
verifyAttestation(credential, trustedAuthorities) → { valid, level, claims }
generateZKProof(credential, statement, merkleRoot) → ZKProof
// statement: { type: 'age_gte', value: 18 }
//            { type: 'claim_is', name: 'journalist', value: true }
//            { type: 'country_is', value: 'CA' }

verifyZKProof(proof, statement, authorityPubKey) → bool
```

#### ZK Proof Flow  (Age example)

```
Setup (once, with any trusted age authority):
  Authority verifies real ID out of band
  Issues signed credential: { birthdate, credId, authoritySignature }
  Credential stored encrypted on device, associated with master key
  Authority adds credId to its Merkle tree
  Authority deletes the PII — it no longer needs it

Presenting to any service, from any persona, at any time:
  App runs ZK circuit locally (1–3 seconds on phone)

  Private inputs (never leave the device):
    - actual birthdate
    - authority's signature over the credential
    - credential ID
    - Merkle path proving inclusion in current tree

  Public output:
    - proof: "age ≥ 18 as of today"
    - credential is in the authority's current valid tree
    - nothing else — no birthdate, no credential ID, no persona link

Service verifies:
  - ZK proof is mathematically valid (< 10ms)
  - Merkle root matches the authority's published root
  - Authority's public key is in the service's trusted list
  - Done. No PII received. No record at the authority. No persona linkage.
```

#### Merkle-Based Revocation

```
Authority publishes a new Merkle root periodically
  L2 (payment):        on change
  L3 (age):            24h acceptable
  L4 (verified human): 1h
  L5 (government ID):  real-time OCSP

Revocation = remove credId from tree → root hash changes
Any proof using a root older than the grace period → rejected

Verifier needs only: the latest root hash (32 bytes — publishable anywhere)
Verifier learns nothing about which leaf the prover occupies
```

#### Composing Peer Trust and Authority Trust

The two trust models are independent and composable. A service can require:
- A trusted contact introduction (peer trust) — "someone I already trust added you"
- An authority attestation (institutional trust) — "you meet this verifiable standard"
- Both — "a trusted contact vouches for you AND you hold a press credential"
- Neither — open access

Neither model depends on the other. A persona without any authority attestations still has a full identity within their web of trust. A persona with attestations can present them to any service without revealing their contacts or vice versa.

---

## 3. Mobile App

### 3.1 iOS Architecture

| Layer | Detail |
|---|---|
| Language | Swift 5.9+, SwiftUI |
| Crypto | CryptoKit + Secure Enclave (P-256). Ed25519 in software. |
| Storage | iOS Keychain (seed), SQLite via GRDB (contacts, records) |
| Cloud backup | CloudKit private container — user's iCloud only |
| Push | APNs — high priority, time-sensitive interruption level |
| Proxy comms | URLSession + WebSocket for real-time auth requests |
| Passkeys | AuthenticationServices framework (WebAuthn) |
| ZK proofs | Swift bindings to noir or snarkjs WASM |

### 3.2 Core User Flows

#### Onboarding  (~2 minutes, no crypto visible)

```
1. Set up device security  (no IDAP-specific PIN)
   → If device has no passcode: prompt user to set one (iOS Settings)
   → generateMasterSeed() internally
   → generateEnclaveKey(label: "idap.master", access: .userPresence)
     kSecAccessControlUserPresence = biometrics OR device passcode, SE-enforced
   → enclaveEncrypt(seed) → store ciphertext in Keychain
     kSecAttrAccessibleWhenUnlockedThisDeviceOnly
   → from this point: daily unlock = Face ID / device passcode via OS, no IDAP PIN

2. Create your first persona  ("the real you")
   → user picks a handle: @alice@idap.app
   → persona key derived at index 0 (m/0')
   → registered at proxy — proxy sees only a public key, nothing else
   → this is their primary real-world identity
   → additional personas (gaming, work, journalist, etc.) added later in app

3. Back up your account  (mandatory, cannot skip)
   → user creates a recovery password (alphanumeric passphrase, no restrictions)
     shown once, user advised to store it separately from device
     this is NOT their device passcode — it's only for new-device recovery
   → backupKey = Argon2id(recoveryPassword, randomSalt, mem=64MB, iter=3)
   → encryptedBlob = AES-256-GCM(seed, backupKey)
   → upload encrypted seed blob to user's iCloud Drive (CloudKit private container)
   → upload plaintext recovery map (empty at this point) alongside it
   → salt stored with blob — no separate secret needed to decrypt

4. Optional: Save recovery phrase
   → show 24 BIP-39 words
   → confirm 4 random words before proceeding
   → most users skip — that's fine, two recovery paths already exist

5. Optional: Add recovery contacts  (prompted after first contact added)
   → "Your contacts can help you recover your account"
   → shard distribution happens silently in background
   → recovery map updated in user's cloud storage
```

#### Initiating a Login

```
1. User is on a website, sees "Login with IDAP" button
   → User opens IDAP app, selects which persona to use
   → Taps "Log in somewhere" (or equivalent)
   → App: POST /oidc/login-code (signed by persona key)
   → App displays: short code "7K3-M9X" + QR code, 5-minute countdown

2. User presents code to the service
   → Types it into the website's login field, or
   → Service scans the QR code directly (better UX), or
   → On same device: tap to open the authorize URL directly

3. Auth request arrives in the app via WebSocket
   → App is already open — no push notification needed
   → (See approval flow below)

4. After first approval → passkey registered silently
   → All future logins to this service use passkey locally
   → No proxy, no push, works offline
```

#### Approving an Auth Request

```
1. Auth request arrives over WebSocket (app is open)
   APNs push is a supplemental path — sent if the app is not open,
   allowing the device to wake and connect. Not required for the core flow.

2. User sees:
   Service name + persona being used
   What claims are being shared
   Location hint + timestamp  (sanity check for user)
   Three numbers — tap the one matching the desktop screen

3. User taps correct number
   → Face ID confirms
   → derivePersonaKey(seed, index) in memory
   → sign JWT assertion with persona key
   → send to proxy via WebSocket
   → key cleared from memory immediately

4. Desktop redirects automatically
   → passkey registered silently for future logins to this service
```

#### Adding a Contact

```
1. Alice taps 'Add contact' → shares her persona link
   idap://add/@alice-gaming@idap.app  or  QR code

2. Bob opens link
   → fetches Alice's public key bundle from her proxy
   → X3DH key agreement → shared secret established
   → Alice's app encrypts her contact card with shared secret
   → sends encrypted card to Bob's proxy inbox

3. Silently in background:
   → Alice's app generates a new Shamir shard
   → encrypts with Bob's public key
   → stores at Bob's proxy
   → updates Alice's recovery map
   → proxy never saw the contact card or shard contents

4. Bob accepts contact, sees Alice's shared info
   → stored locally in encrypted contacts.db
```

---

## 4. Prototype Build Order

Build in this order. Each phase is independently demonstrable.

| Phase | What to Build | Demo |
|---|---|---|
| **1 — Crypto Core** | idap-crypto library. Key gen, persona derivation, Shamir, encrypt/decrypt. Unit tested. | Console: generate key, derive 3 personas, split/reconstruct seed |
| **2 — Proxy MVP** | idap-proxy in Go. Key registration, inbox, WebFinger. SQLite. Single binary. | Two proxy instances talking. Keys resolvable cross-proxy. |
| **3 — OIDC Flow** | Add OIDC endpoints to proxy. iOS app shell that receives push + signs JWT. | Real website uses "Login with IDAP". Phone approves. Redirected in. |
| **4 — Contacts** | idap-contacts. X3DH exchange, encrypted local DB, background shard distribution. | Two phones add each other. See shared PII locally. Nothing on server. |
| **5 — Recovery** | idap-recovery. Recovery map, code generation, shard redemption. | Simulate losing phone. Recover via contact code + password on new device. |
| **6 — Credentials** | idap-attestation basic. Issue signed age credential. ZK proof of age ≥ 18. | Service requests age proof. Phone proves it. Service verifies. Zero PII. |
| **7 — Self-Hosted Server Library** | Minimal key-based auth library in Go, Node, Python. Spec the challenge/verify wire format. | Add IDAP auth to any self-hosted service in under an hour. Invite a friend via link. They need no account. |

**Phase 3 is the hook for mainstream users.** Once "Login with IDAP" works on a real website, the value proposition is immediately demonstrable to anyone.

**Phase 7 is the hook for self-hosters.** A minimal, well-documented server library in multiple languages is the artifact that gets IDAP into the self-hosted ecosystem. Everything else people build on top — portals, dashboards, bots — is up to them. The protocol just needs to make the primitive solid.

---

## 5. Tech Stack Summary

| Component | Language / Framework | Key Libraries |
|---|---|---|
| idap-crypto | Swift / Kotlin / TS | CryptoKit, bip39, noble-curves, shamir-secret-sharing |
| idap-identity | Swift / Kotlin / TS | idap-crypto, sqlite (GRDB on iOS) |
| idap-contacts | Swift / Kotlin / TS | idap-crypto, idap-identity |
| idap-auth | Swift / Kotlin / TS | AuthenticationServices (WebAuthn), APNs |
| idap-recovery | Swift / Kotlin / TS | idap-crypto, idap-contacts |
| idap-attestation | TS (verify) / Go (server) | snarkjs / noir (ZK), merkle-tree |
| idap-proxy | Go | zitadel/oidc, gorilla/websocket, mattn/go-sqlite3 |
| idap-server-auth | Go / Node / Python / Rust | ed25519 verify, minimal — no external deps |
| iOS App | Swift / SwiftUI | All idap-* libraries, GRDB, CloudKit |

---

## 6. Open Questions for Community Review

- **ZK proof library:** noir vs circom/snarkjs — which has the better mobile story?
- **Curve choice:** Ed25519 vs P-256 throughout — P-256 required for Secure Enclave, worth standardising on?
- **Proxy federation:** WebFinger sufficient or do we need an additional discovery layer?
- **Revocation latency:** what is acceptable per trust level? 24h for L3, 1h for L4, real-time for L5?
- **Metadata minimisation:** should the proxy log sender handles at all, or route blind?
- **Key rotation:** how frequently should persona keys rotate — user-triggered only, or scheduled?
- **Attestation accountability:** how do we handle a provider issuing fraudulent credentials?
- **Self-hosted push:** for self-hosted proxies without APNs access, is WebSocket-only delivery acceptable UX, or should the spec define an optional push relay interface?
- **Self-hosted discovery:** DNS SRV records, or rely entirely on WebFinger?
- **Inbox token replenishment:** how does a client know when to publish fresh tokens? Proactive (publish N at registration, refill below threshold) or on-demand?
- **PoW difficulty tuning:** what difficulty target is appropriate at launch, and what's the adjustment mechanism as hardware improves?
- **Login code UX:** short typed code vs QR-only vs deep link — what's the right primary UX for desktop-to-phone login initiation?
- **Pairwise sub and JWKS resolution:** if `sub` is a pairwise HMAC and not the handle, how does a service resolve the JWKS URL for JWT verification? Options: `iss` contains the proxy URL and the service hits `{iss}/jwks?sub={sub}`, or the token includes a `kid` that encodes enough to find the right key without revealing the handle.
- **Field revocation delivery:** if a contact is offline when a field revocation is sent, their inbox holds the revocation message. How long should revocations be retained, and should the app re-send on reconnect?
- **Key-based auth server library:** what's the minimal interface a server needs to implement to accept IDAP key-based auth? Should the spec define a standard challenge format and response schema, or leave it to implementors?
- **Invite token scope:** should invite tokens encode which fields the server requests, or should that be a separate negotiation after key registration?

---

## 7. Threat Model

### What IDAP protects

| Threat | Protection |
|--------|-----------|
| Service stores your PII | Services receive only `sub` (persona handle) by default. PII sharing is explicit, per-field, revocable. |
| Proxy reads your messages | Inbox, shards, and contact cards are encrypted client-side. Proxy stores opaque blobs. |
| Persona A linked to Persona B by a service | Each persona has independent keys, handles, contact lists. Services see no shared identifier. |
| Passkey phishing | Number-match requires the user to visually verify a value shown on the target device. |
| Credential theft without device | Persona keys are never stored — derived on demand from a seed that never leaves the device unencrypted. |
| Auth request tampering | Signed assertion verified directly against the persona's registered public key. Proxy cannot forge or modify. |

### What IDAP does not protect

**Proxy operator correlation.** If two personas are registered at the same proxy, the proxy operator can correlate them by IP address and timing — every time the app unlocks, both personas appear from the same origin. This is an operational reality, not a cryptographic failure. The proxy has no mathematical link between personas; the correlation is purely observational.

*Mitigation:* Use a different proxy per persona for sensitive separations. The persona creation UI exposes this choice explicitly. Personas on different proxies are not correlatable by either proxy operator.

**IP-level and network correlation.** A network observer (ISP, VPN provider, etc.) can see that a single device communicates with multiple proxy servers. Timing attacks remain possible for well-resourced adversaries. No protocol-level mitigation exists for this.

**Apple infrastructure visibility.** APNs push notifications pass through Apple's servers. Apple observes: device token, timestamp, app ID. No payload content is visible — push bodies are encrypted in transit — but the existence and timing of auth events is metadata Apple can see.

*Mitigation:* APNs is not required for the core auth flow (see login codes, section 2.4). Self-hosted deployments use WebSocket-only delivery. APNs is a UX enhancement for background wake, not a security dependency.

**Proxy operator abuse.** A malicious proxy operator can: drop messages, deny service to specific handles, observe which services a user logs into (from OIDC authorize calls), and see inbox message timing (not content). They cannot: read encrypted payloads, forge assertions, or link personas on different proxies.

*Mitigation:* Self-hosting eliminates the trusted-operator requirement. For managed hosting, the protocol minimises what the operator learns — service names are visible in OIDC sessions, but no PII.

### Abuse vectors

**Inbox spam.** The inbox `POST` endpoint is intentionally unauthenticated — unknown contacts need to be able to reach you. This is exploitable for bulk delivery of garbage.

*Planned mitigation:* Inbox tokens. When sharing a contact link (`idap://add/...`), the link embeds a single-use token. The proxy requires a valid unconsumed token for first delivery from an unknown sender. Established contacts bypass token checks. Token exhaustion means "not accepting cold contact currently" — a reasonable social signal. Mirrors the one-time pre-key mechanism already in the key bundle.

**OIDC flooding.** Without controls, an attacker knowing a persona handle could initiate unlimited fake auth requests, creating notification fatigue and potential approval confusion.

*Resolution:* The login code model (section 2.4) closes this entirely. A service cannot initiate an auth request without presenting a code generated by an authenticated app session. No code = no request. The attacker would need to compromise the user's device to generate a valid code.

**Account creation abuse / Sybil attacks.** Registration is free and unlimited. Nothing prevents bulk creation of personas, which wastes proxy storage and enables Sybil attacks on contact-based systems.

*Planned mitigation:* Proof of work on registration. A `POST /register` call must include a nonce such that `SHA256(proposed_id + nonce)` meets a difficulty target. Adjustable difficulty. Makes bulk creation expensive without requiring identity. Complements opaque random IDs (planned), which remove the incentive to squat on specific handles.

**Unused ID accumulation.** Even with PoW, IDs that register and go dark consume storage indefinitely.

*Planned mitigation:* Expiry of inactive IDs. Any ID that has had no key update, inbox activity, or WebSocket connection in 90 days is eligible for pruning. Proxy warns via the key bundle metadata before pruning. Legitimate active users are unaffected.

### Trust hierarchy summary

```
User's device         — Trusted completely. Holds keys. Source of truth.
User's own cloud      — Trusted for encrypted backup only. Cannot decrypt without device key.
Proxy operator        — Trusted for availability and routing. Cannot read content.
                        Can observe: handle existence, service names (OIDC), message timing.
                        Cannot observe: message content, persona linkage across proxies.
Relying party         — Trusted only after explicit user approval.
                        Receives: sub claim (handle), approved scopes only.
                        Never receives: master identity, other personas, PII not explicitly shared.
Apple / Google        — Trusted for push delivery timing metadata only.
                        Cannot read payloads. Core flow does not depend on them.
Network / ISP         — Untrusted. Sees: which proxies you connect to, timing.
                        Does not see: content (TLS), which handles are yours.
```

---

> **This is an open source project seeking security review.**
>
> The cryptographic primitives used (Ed25519, X25519, AES-256-GCM, BIP-32, Shamir SSS, X3DH, WebAuthn/FIDO2) are all well-established and independently audited. The novelty is in their composition and the UX layer, not in new cryptography.
>
> Please break it. That's the point.
