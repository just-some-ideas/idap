# idap-recovery

Recovery map management, shard encryption, timed codes, seed reconstruction, and key migration for the IDAP protocol.

## Role in IDAP

Implements all recovery flows: generating and storing recovery maps, encrypting shards for contacts (X25519) and with passwords (KDF), generating and verifying timed recovery codes, reconstructing the master seed from collected shards, and creating signed migration records for key/proxy changes.

## API Overview

### Key Types

```swift
struct RecoveryMap: Codable {
    let scheme: String           // e.g. "2-of-4"
    let entries: [ShardEntry]
    var k: Int                   // threshold (computed)
    var n: Int                   // total shards (computed)
}

struct ShardEntry: Codable {
    let shardId: String
    let holderKey: String        // base64 public key of holder
    let method: String           // "contact" or "proxy"
}

struct TimedCode {
    let code: String             // formatted "XX-XX-XX-XX"
    let shardId: String
    let expiresAt: Date
    let nonce: Data
    let signature: Data
}

struct SignedMigration: Codable {
    let oldPublicKey: String
    let newPublicKey: String
    let newProxy: String
    let timestamp: String
    let signature: String
}
```

### Recovery Map

```swift
let recovery = IDAPRecovery(store: InMemoryRecoveryMapStore())

// Generate a 2-of-n recovery map from contacts
let map = recovery.generateRecoveryMap(seed: seed, contacts: contacts)
// Splits seed into shards, assigns one per contact

try recovery.saveRecoveryMap(map)       // persist to user's cloud storage
let map = try recovery.fetchRecoveryMap()
```

### Shard Encryption

```swift
// For contacts: ephemeral X25519 + HKDF + AES-GCM
let encrypted = recovery.encryptShardForContact(shard, contactIdentityPublicKey: key)
let shard = recovery.decryptShardForContact(encrypted, myPrivateKey: privateKey)

// For password-protected shards (proxy storage)
let encrypted = recovery.encryptShardWithPassword(shard, password: "recovery-passphrase")
let shard = recovery.decryptShardWithPassword(encrypted, password: "recovery-passphrase")
```

### Timed Recovery Codes

```swift
// Contact generates a code to help with recovery
let code = recovery.generateTimedCode(shardId: "a3f9", privateKey: contactPrivateKey)
// code.code = "4X-7K2-9M", valid 15 minutes, one-time use

// Verify code hasn't expired
let valid = recovery.isTimedCodeValid(code)
```

Codes use HMAC-SHA256, encoded as Crockford base32. They must be delivered verbally — the UI should instruct users not to text them.

### Seed Reconstruction

```swift
// Collect k shards from contacts, then reconstruct
let seed = recovery.reconstructSeed(collectedShards)
// Delegates to IDAPCrypto.reconstructSecret (Lagrange interpolation)
```

### Key Migration

```swift
// Create a signed migration record when changing key or proxy
let migration = recovery.createMigrationRecord(
    oldPublicKey: oldKey, newPublicKey: newKey,
    newProxy: newProxyURL, oldPrivateKey: oldPrivateKey
)

// Verify a migration record from a contact
let valid = recovery.verifyMigrationRecord(migration, oldPublicKey: oldPubKey)
```

### Clock Injection (Testing)

```swift
let clock = MockClock(currentDate: Date())
let recovery = IDAPRecovery(store: store, clock: clock)

clock.advance(by: 900)  // 15 minutes
recovery.isTimedCodeValid(code)  // → false (expired)
```

## Dependencies

| Package | Why |
|---------|-----|
| `idap-crypto` | Shamir splitting/reconstruction, X25519, HKDF, AES-GCM, Ed25519 signing |
| `idap-contacts` | Contact model for shard assignment |

## Testing

```sh
cd packages/idap-recovery
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

21 tests covering: recovery map generation, save/fetch, shard encryption (contact and password), timed code generation and expiry, seed reconstruction, migration record creation and verification.

## Status

Implemented: recovery map, shard encryption (contact + password), timed codes, seed reconstruction, key migration. Not yet implemented: Argon2id for password-based KDF (currently uses HKDF — production should use Argon2id), hardware key shard path.
