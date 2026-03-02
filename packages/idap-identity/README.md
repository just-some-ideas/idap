# idap-identity

Persona management, credential wallet, and W3C Verifiable Credential signing for the IDAP protocol.

## Role in IDAP

Implements the persona lifecycle — creating, listing, and deleting personas with deterministic key derivation. Manages a credential wallet for storing and presenting signed records (W3C VC format). Maintains the derivation index registry to ensure deleted persona indices are never reused.

## API Overview

### Key Types

```swift
struct Persona {
    let id: String                    // "real", "gaming", custom
    let derivationIndex: UInt32       // BIP-32 index
    let publicKey: Data               // Ed25519 (32 bytes)
    let proxy: URL
    let fallbackProxy: URL?
    let reliability: Reliability      // .critical, .bestEffort, .relaxed
    let keySource: KeySource          // .secureEnclave, .software, .hardwareKey
    let publicProfile: PersonaProfile?
}

struct Credential: Codable { ... }    // W3C VC fields
struct SignedRecord: Codable { ... }  // signed W3C VC with proof
struct VerifyResult {
    let valid: Bool
    let issuer: String
    let subject: String
}
```

### Persona Lifecycle

```swift
let identity = try IDAPIdentity(db: databaseQueue)

let persona = identity.createPersona(seed: seed, index: 0, proxy: proxyURL)
let personas = identity.listPersonas()
identity.deletePersona(persona)

let nextIndex = identity.nextDerivationIndex()    // safe — never reuses deleted indices
```

### On-Demand Key Derivation

```swift
let keyPair = identity.getPersonaKey(persona: persona, seed: seed)

// Or with automatic cleanup:
identity.withPersonaKey(persona: persona, seed: seed) { keyPair in
    // use keyPair.privateKey — zeroed after block returns
}
```

### Credential Wallet

```swift
identity.storeCredential(credential, for: persona)
let credentials = identity.listCredentials(for: persona)
let credential = identity.getCredential(type: "AgeCredential", for: persona)
```

### Signed Records (W3C VC)

```swift
let signed = identity.signRecord(unsignedRecord, persona: persona, seed: seed)
let result = identity.verifyRecord(signed)  // → VerifyResult { valid, issuer, subject }
```

### DID Generation

```swift
let did = IDAPIdentity.makeDID(publicKey: publicKey)
// → "did:idap:persona:<base58(sha256(publicKey))>"
```

## Dependencies

| Package | Why |
|---------|-----|
| `idap-crypto` | Ed25519 key derivation and signing |
| `GRDB.swift` | SQLite storage for personas, credentials, derivation registry |

## Testing

```sh
cd packages/idap-identity
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

19 tests covering: persona creation, listing, deletion, index allocation, derivation registry, credential CRUD, signed record creation, signature verification, and DID generation.

## Status

Implemented: persona lifecycle, credential wallet, signed records, derivation registry. Not yet implemented: pairwise identity mode (per-service derived keys), multi-device registry sync.
