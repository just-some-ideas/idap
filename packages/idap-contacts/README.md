# idap-contacts

X3DH contact exchange, encrypted contact book, and PII field sharing for the IDAP protocol.

## Role in IDAP

Implements the contact exchange protocol using Extended Triple Diffie-Hellman (X3DH) for establishing shared secrets between contacts. Manages the encrypted local contact book. Handles per-field PII sharing and revocation. Also provides shard encryption for distributing recovery shards to contacts.

## API Overview

### Key Types

```swift
struct ContactKeyBundle: Codable {
    let personaId: String
    let identityPublicKey: Data
    let signedPreKey: Data
    let signedPreKeySignature: Data
    let oneTimePreKeys: [Data]
}

struct X3DHResult {
    let sharedSecret: Data
    let ephemeralPublicKey: Data
    let usedOneTimePreKeyIndex: Int?
}

struct Contact {
    let id: String
    let personaId: String
    let publicKey: Data
    let identityPublicKey: Data
    let sharedSecret: Data
    let displayName: String?
    // ... other fields
}

struct ContactCard: Codable {
    let publicKey: Data
    let identityPublicKey: Data
    let displayName: String?
    let email: String?
    let phone: String?
    let avatarHash: String?
}

enum ContactField { case name, email, phone, avatar }
```

### X3DH Key Agreement

```swift
let contacts = try IDAPContacts(db: databaseQueue)

// Generate key bundle for publishing to proxy
let bundle = contacts.generateKeyBundle(persona: persona, seed: seed, oneTimePreKeyCount: 5)

// Alice initiates contact with Bob
let result = contacts.x3dhInitiate(myBundle: aliceBundle, theirBundle: bobPublicBundle, verifyWith: bobIdentityKey)
// result.sharedSecret — use for encrypting contact card

// Bob responds
let sharedSecret = contacts.x3dhRespond(myBundle: bobBundle, initiatorIdentityPublicKey: aliceIdentityKey, ephemeralPublicKey: result.ephemeralPublicKey, usedOneTimePreKeyIndex: result.usedOneTimePreKeyIndex)
```

### Contact Card Exchange

```swift
// Encrypt contact card with X3DH shared secret
let encrypted = contacts.encryptContactCard(card, sharedSecret: sharedSecret)
// → send encrypted data to contact's inbox

// Decrypt received contact card
let card = contacts.decryptContactCard(data, sharedSecret: sharedSecret)
```

### Contact Management

```swift
contacts.storeContact(contact)
let all = contacts.listContacts(persona: persona)
let one = contacts.getContact(publicKey: key, persona: persona)
contacts.removeContact(contact)
```

### PII Field Sharing

```swift
// Share a field with a contact
let encrypted = contacts.encryptFieldUpdate(field: .email, value: "alice@example.com", sharedSecret: secret)

// Revoke a field
let revocation = contacts.encryptFieldRevocation(field: .email, sharedSecret: secret)

// Decrypt a received field update
let update = contacts.decryptFieldUpdate(data, sharedSecret: secret)
// update.field = .email, update.value = "alice@example.com" (or nil for revocation)
```

### Recovery Shard Distribution

```swift
// Encrypt a Shamir shard for a contact using their identity public key
let encrypted = contacts.encryptShardForContact(shard, identityPublicKey: contactKey)

// Decrypt a shard received from a contact
let shard = contacts.decryptShardFromContact(encrypted, myPrivateKey: myKey)
```

Shard encryption uses ephemeral X25519 key agreement + HKDF + AES-256-GCM.

## Dependencies

| Package | Why |
|---------|-----|
| `idap-crypto` | X25519, HKDF, AES-GCM, Ed25519 verification |
| `idap-identity` | Persona model |
| `GRDB.swift` | SQLite storage for contacts |

## Testing

```sh
cd packages/idap-contacts
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

17 tests covering: key bundle generation, X3DH initiate and respond, shared secret agreement, contact card encrypt/decrypt, contact CRUD, field sharing and revocation, and shard encryption round-trip.

## Status

Implemented: X3DH key agreement, capability negotiation (request/grant/denial/revocation), contact card exchange, encrypted contact storage, field sharing/revocation, shard encryption for contacts, first-message encryption (ephemeral X25519 + AES-GCM). The iOS app primarily uses the capability-request flow for contact exchange rather than full X3DH — see [protocol docs](../../docs/protocol.md#74-capability-negotiation). Not yet implemented: inbox token management, service-type contacts (key-based auth for self-hosted services).
