# idap-crypto

Pure cryptographic primitives for the IDAP protocol. No network, no storage, no side effects. This is the foundation that all other packages build on.

## Role in IDAP

Implements every cryptographic operation the protocol requires: seed generation, mnemonic encoding, deterministic key derivation, signing, encryption, key agreement, and secret sharing. All other IDAP packages depend on this one.

## API Overview

All functions are static methods on the `IDAPCrypto` enum.

### Key Types

```swift
struct KeyPair {
    let publicKey: Data   // 32 bytes
    let privateKey: Data  // 32 or 64 bytes depending on algorithm
}

struct EncryptedPayload {
    let ciphertext: Data
    let nonce: Data       // 12 bytes
    let tag: Data         // 16 bytes
}

struct Share {
    let id: UInt8         // share identifier (1...n)
    let value: Data       // same length as original secret
}
```

### Seed & Mnemonic (BIP-39)

```swift
IDAPCrypto.generateMasterSeed() -> Data                    // 32-byte random seed
IDAPCrypto.seedToMnemonic(_ seed: Data) -> [String]        // 24 BIP-39 words
IDAPCrypto.mnemonicToSeed(_ words: [String]) -> Data?      // words back to seed (validates checksum)
```

### Key Derivation (SLIP-0010 / BIP-32)

```swift
IDAPCrypto.derivePersonaKey(seed: Data, index: UInt32) -> KeyPair     // Ed25519 at m/index'
IDAPCrypto.derivePersonaKeyP256(seed: Data, index: UInt32) -> KeyPair // P-256 at m/index'
```

### Signing (Ed25519)

```swift
IDAPCrypto.sign(privateKey: Data, message: Data) -> Data
IDAPCrypto.verify(publicKey: Data, message: Data, signature: Data) -> Bool
```

### Encryption (AES-256-GCM)

```swift
IDAPCrypto.encrypt(key: Data, plaintext: Data) -> EncryptedPayload
IDAPCrypto.decrypt(key: Data, payload: EncryptedPayload) -> Data?
```

### Key Agreement (X25519 + HKDF)

```swift
IDAPCrypto.generateEphemeralX25519() -> KeyPair
IDAPCrypto.generateEphemeralX25519FromSeed(_ seed: Data) -> KeyPair   // deterministic
IDAPCrypto.deriveSharedSecret(myPrivate: Data, theirPublic: Data) -> Data
IDAPCrypto.hkdf(secret: Data, salt: Data, info: Data, length: Int) -> Data
```

### Secure Enclave (iOS)

```swift
IDAPCrypto.generateEnclaveKey(label: String) -> Data?      // P-256, hardware-backed
IDAPCrypto.enclaveEncrypt(label: String, data: Data) -> Data?
IDAPCrypto.enclaveDecrypt(label: String, ciphertext: Data) -> Data?
```

Returns `nil` on simulator (no Secure Enclave available).

### Shamir Secret Sharing

```swift
IDAPCrypto.splitSecret(_ secret: Data, k: Int, n: Int) -> [Share]    // k-of-n split
IDAPCrypto.reconstructSecret(_ shares: [Share]) -> Data?              // reconstruct from k shares
```

## Dependencies

None beyond platform frameworks (`CryptoKit`, `Security`, `Foundation`). The BIP-39 English wordlist is bundled as a resource.

## Testing

```sh
cd packages/idap-crypto
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

25 tests covering: seed generation, mnemonic round-trip, Ed25519 derivation + signing, P-256 derivation, AES-GCM encrypt/decrypt, X25519 key agreement, HKDF, and Shamir split/reconstruct.

## Status

All protocol-required cryptographic primitives are implemented. Secure Enclave functions require a physical iOS device.
