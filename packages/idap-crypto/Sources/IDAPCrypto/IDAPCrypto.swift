// IDAPCrypto — cryptographic primitives for IDAP
// No network, no storage, no side effects. Pure functions only.

import CryptoKit
import Foundation
import Security

// MARK: - Base64URL Extensions

extension Data {
    /// Encode to base64url (RFC 4648 §5, no padding).
    public func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode from base64url (RFC 4648 §5, with or without padding).
    public init?(base64URLEncoded str: String) {
        var s = str
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Add padding if needed
        let remainder = s.count % 4
        if remainder != 0 { s += String(repeating: "=", count: 4 - remainder) }
        self.init(base64Encoded: s)
    }
}

// MARK: - Typed Key Types

/// Key algorithm type for wire-format keys.
public enum KeyType: String, Codable, Equatable, Sendable {
    case ed25519
    case x25519
    case p256
}

/// A typed public key for wire transmission: `{"kty":"ed25519","key":"<base64url>"}`.
public struct TypedKey: Codable, Equatable, Sendable {
    public let kty: KeyType
    public let key: String  // base64url-encoded raw public key bytes

    public init(kty: KeyType, rawKey: Data) {
        self.kty = kty
        self.key = rawKey.base64URLEncodedString()
    }

    /// Decode the key bytes from the base64url string.
    public func decode() -> Data? {
        Data(base64URLEncoded: key)
    }
}

/// A typed key pair: typed public key + raw private key bytes.
public struct TypedKeyPair: Equatable {
    public let publicKey: TypedKey
    public let privateKey: Data

    public init(publicKey: TypedKey, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

// MARK: - Public Types

public struct KeyPair {
    public let publicKey: Data
    public let privateKey: Data
    public init(publicKey: Data, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

public struct EncryptedPayload {
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public init(ciphertext: Data, nonce: Data, tag: Data) {
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
    }
}

public struct Share {
    public let id: UInt8
    public let value: Data
    public init(id: UInt8, value: Data) {
        self.id = id
        self.value = value
    }
}

// MARK: - IDAPCrypto

public enum IDAPCrypto {

    // MARK: - BIP-39

    static let wordlist: [String] = {
        guard let url = Bundle.module.url(forResource: "bip39-english", withExtension: "txt"),
              let content = try? String(contentsOf: url, encoding: .utf8)
        else {
            fatalError("IDAPCrypto: missing bip39-english.txt resource")
        }
        return content.components(separatedBy: .newlines).filter { !$0.isEmpty }
    }()

    /// Generate a cryptographically random 32-byte master seed.
    public static func generateMasterSeed() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let result = SecRandomCopyBytes(kSecRandomDefault, 32, &bytes)
        precondition(result == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(bytes)
    }

    /// Encode 32 bytes of entropy to 24 BIP-39 mnemonic words.
    public static func seedToMnemonic(_ seed: Data) -> [String] {
        precondition(seed.count == 32, "seed must be 32 bytes")
        // 256-bit entropy + 8-bit checksum (first byte of SHA256(entropy)) = 264 bits
        let hash = SHA256.hash(data: seed)
        let checksumByte = hash.withUnsafeBytes { $0[0] as UInt8 }

        // Pack into 33-byte array: 32 entropy bytes + 1 checksum byte
        var bits = [UInt8](repeating: 0, count: 33)
        seed.copyBytes(to: &bits, count: 32)
        bits[32] = checksumByte

        // Extract 24 × 11-bit indices
        var words = [String]()
        words.reserveCapacity(24)
        for i in 0..<24 {
            let bitIndex = i * 11
            let byteIndex = bitIndex / 8
            let bitOffset = bitIndex % 8  // how many bits into byteIndex we start

            // Pack up to 3 bytes around this position into a 24-bit window
            var window: UInt32 = UInt32(bits[byteIndex]) << 16
            if byteIndex + 1 < 33 { window |= UInt32(bits[byteIndex + 1]) << 8 }
            if byteIndex + 2 < 33 { window |= UInt32(bits[byteIndex + 2]) }

            // The 11 bits start at bit position `bitOffset` within the 24-bit window
            // Shift right so the 11 bits end up in positions [0..10]
            let shift = 24 - 11 - bitOffset
            let index = Int((window >> shift) & 0x7FF)
            words.append(wordlist[index])
        }
        return words
    }

    /// Decode 24 BIP-39 words back to 32-byte entropy. Returns nil on invalid input or checksum failure.
    public static func mnemonicToSeed(_ words: [String]) -> Data? {
        guard words.count == 24 else { return nil }

        // Map each word to its index
        var indices = [Int]()
        indices.reserveCapacity(24)
        for word in words {
            guard let idx = wordlist.firstIndex(of: word) else { return nil }
            indices.append(idx)
        }

        // Reconstruct 264 bits (33 bytes) from 24 × 11-bit indices
        var bits = [UInt8](repeating: 0, count: 33)
        for (i, idx) in indices.enumerated() {
            let bitIndex = i * 11
            let byteIndex = bitIndex / 8
            let bitOffset = bitIndex % 8  // how many bits into byteIndex we start

            // Spread 11-bit index into the byte array
            // idx occupies bits at positions bitOffset .. bitOffset+10 from the left of byteIndex
            let v = UInt32(idx) << (32 - 11 - bitOffset)
            bits[byteIndex]     |= UInt8((v >> 24) & 0xFF)
            if byteIndex + 1 < 33 { bits[byteIndex + 1] |= UInt8((v >> 16) & 0xFF) }
            if byteIndex + 2 < 33 { bits[byteIndex + 2] |= UInt8((v >> 8) & 0xFF) }
        }

        let entropy = Data(bits[0..<32])
        let storedChecksum = bits[32]

        // Verify: first byte of SHA256(entropy) must equal storedChecksum
        let hash = SHA256.hash(data: entropy)
        let computedChecksum = hash.withUnsafeBytes { $0[0] as UInt8 }
        guard storedChecksum == computedChecksum else { return nil }
        return entropy
    }

    // MARK: - BIP-32 / SLIP-0010 Key Derivation

    /// Derive a hardened Ed25519 persona key at m/index' using SLIP-0010.
    public static func derivePersonaKey(seed: Data, index: UInt32) -> KeyPair {
        // SLIP-0010 master key for Ed25519
        let master = hmacSHA512(key: Data("ed25519 seed".utf8), data: seed)
        let masterPriv = master[0..<32]
        let masterChain = master[32..<64]

        // Hardened child derivation: 0x00 || IL || ser32(index | 0x80000000)
        let hardenedIndex = index | 0x8000_0000
        var childData = Data([0x00])
        childData.append(masterPriv)
        childData.append(ser32(hardenedIndex))
        let child = hmacSHA512(key: masterChain, data: childData)
        let childPriv = child[0..<32]

        let privKey = try! Curve25519.Signing.PrivateKey(rawRepresentation: childPriv)
        return KeyPair(
            publicKey: privKey.publicKey.rawRepresentation,
            privateKey: Data(childPriv)
        )
    }

    /// Derive a hardened P-256 persona key at m/index' using BIP-32.
    public static func derivePersonaKeyP256(seed: Data, index: UInt32) -> KeyPair {
        let master = hmacSHA512(key: Data("Bitcoin seed".utf8), data: seed)
        let masterPriv = master[0..<32]
        let masterChain = master[32..<64]

        let hardenedIndex = index | 0x8000_0000
        var childData = Data([0x00])
        childData.append(masterPriv)
        childData.append(ser32(hardenedIndex))
        let child = hmacSHA512(key: masterChain, data: childData)
        let childPriv = child[0..<32]

        let privKey = try! P256.Signing.PrivateKey(rawRepresentation: childPriv)
        return KeyPair(
            publicKey: privKey.publicKey.rawRepresentation,
            privateKey: Data(childPriv)
        )
    }

    // MARK: - Ed25519 Sign & Verify

    public static func sign(privateKey: Data, message: Data) -> Data {
        let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        return (try? key.signature(for: message)) ?? Data()
    }

    public static func verify(publicKey: Data, message: Data, signature: Data) -> Bool {
        guard let key = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else {
            return false
        }
        return key.isValidSignature(signature, for: message)
    }

    // MARK: - AES-256-GCM

    public static func encrypt(key: Data, plaintext: Data) -> EncryptedPayload {
        let symmetricKey = SymmetricKey(data: key)
        let nonce = AES.GCM.Nonce()
        // CryptoKit combines ciphertext + 16-byte tag in the sealed box
        let sealed = try! AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
        // Materialise as fresh contiguous Data objects to ensure 0-based indexing
        return EncryptedPayload(
            ciphertext: Data(sealed.ciphertext),
            nonce: Data(nonce),
            tag: Data(sealed.tag)
        )
    }

    public static func decrypt(key: Data, payload: EncryptedPayload) -> Data? {
        let symmetricKey = SymmetricKey(data: key)
        guard let nonce = try? AES.GCM.Nonce(data: payload.nonce) else { return nil }
        guard let sealedBox = try? AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: payload.ciphertext,
            tag: payload.tag
        ) else { return nil }
        return try? AES.GCM.open(sealedBox, using: symmetricKey)
    }

    // MARK: - X25519 Key Agreement + HKDF

    public static func generateEphemeralX25519() -> KeyPair {
        let privKey = Curve25519.KeyAgreement.PrivateKey()
        return KeyPair(
            publicKey: privKey.publicKey.rawRepresentation,
            privateKey: privKey.rawRepresentation
        )
    }

    /// Derive a deterministic X25519 key pair from 32 seed bytes.
    public static func generateEphemeralX25519FromSeed(_ seed: Data) -> KeyPair {
        precondition(seed.count == 32)
        let privKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed)
        return KeyPair(
            publicKey: privKey.publicKey.rawRepresentation,
            privateKey: privKey.rawRepresentation
        )
    }

    /// Perform X25519 key agreement, returning the raw 32-byte shared secret.
    public static func deriveSharedSecret(myPrivate: Data, theirPublic: Data) -> Data {
        let privKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: myPrivate)
        let pubKey = try! Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublic)
        let shared = try! privKey.sharedSecretFromKeyAgreement(with: pubKey)
        return shared.withUnsafeBytes { Data($0) }
    }

    /// HKDF-SHA256 key derivation.
    public static func hkdf(secret: Data, salt: Data, info: Data, length: Int) -> Data {
        let ikm = SymmetricKey(data: secret)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputByteCount: length
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    // MARK: - Secure Enclave

    /// Generate a P-256 key in the Secure Enclave. Returns the public key bytes, or nil on simulator.
    public static func generateEnclaveKey(label: String) -> Data? {
        guard SecureEnclave.isAvailable else { return nil }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &error
        ), error == nil else { return nil }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: label.data(using: .utf8)!,
                kSecAttrAccessControl as String: access
            ]
        ]
        var cfErr: Unmanaged<CFError>?
        guard let privKey = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr),
              cfErr == nil,
              let pubKey = SecKeyCopyPublicKey(privKey) else { return nil }
        var copyErr: Unmanaged<CFError>?
        guard let pubData = SecKeyCopyExternalRepresentation(pubKey, &copyErr) as Data?,
              copyErr == nil else { return nil }
        return pubData
    }

    /// Encrypt data using a Secure Enclave P-256 key identified by label.
    public static func enclaveEncrypt(label: String, data: Data) -> Data? {
        guard SecureEnclave.isAvailable else { return nil }
        guard let privKey = findEnclaveKey(label: label),
              let pubKey = SecKeyCopyPublicKey(privKey) else { return nil }
        var err: Unmanaged<CFError>?
        let result = SecKeyCreateEncryptedData(
            pubKey,
            .eciesEncryptionStandardVariableIVX963SHA256AESGCM,
            data as CFData,
            &err
        )
        guard err == nil, let encrypted = result else { return nil }
        return encrypted as Data
    }

    /// Decrypt data using a Secure Enclave P-256 key identified by label.
    /// Biometric/passcode prompt is handled by the OS.
    public static func enclaveDecrypt(label: String, ciphertext: Data) -> Data? {
        guard SecureEnclave.isAvailable else { return nil }
        guard let privKey = findEnclaveKey(label: label) else { return nil }
        var err: Unmanaged<CFError>?
        let result = SecKeyCreateDecryptedData(
            privKey,
            .eciesEncryptionStandardVariableIVX963SHA256AESGCM,
            ciphertext as CFData,
            &err
        )
        guard err == nil, let decrypted = result else { return nil }
        return decrypted as Data
    }

    private static func findEnclaveKey(label: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: label.data(using: .utf8)!,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        // swiftlint:disable force_cast
        return (item as! SecKey)
    }

    // MARK: - Shamir Secret Sharing over GF(2^8)

    // GF(2^8) using AES polynomial x^8+x^4+x^3+x+1 (reducing polynomial 0x11B)
    static func gfMul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var a = a, b = b, result: UInt8 = 0
        while b != 0 {
            if (b & 1) != 0 { result ^= a }
            let hiBitSet = (a & 0x80) != 0
            a = a << 1
            if hiBitSet { a ^= 0x1B }
            b >>= 1
        }
        return result
    }

    static func gfInverse(_ a: UInt8) -> UInt8 {
        precondition(a != 0, "GF(256) division by zero")
        // Fermat's little theorem: a^(256-2) = a^254 = a^(-1) in GF(256)
        var result: UInt8 = 1
        var base = a
        var exp = 254
        while exp > 0 {
            if (exp & 1) != 0 { result = gfMul(result, base) }
            base = gfMul(base, base)
            exp >>= 1
        }
        return result
    }

    /// Split a secret into n shares using k-of-n Shamir Secret Sharing over GF(256).
    public static func splitSecret(_ secret: Data, k: Int, n: Int) -> [Share] {
        precondition(k >= 2 && n >= k && n <= 255)
        // Initialize share values
        var shareValues = [[UInt8]](repeating: [UInt8](repeating: 0, count: secret.count), count: n)

        for byteIdx in 0..<secret.count {
            // Random polynomial f(x) of degree k-1, with f(0) = secretByte
            var coeffs = [UInt8](repeating: 0, count: k)
            coeffs[0] = secret[byteIdx]
            for c in 1..<k {
                var rand: UInt8 = 0
                _ = SecRandomCopyBytes(kSecRandomDefault, 1, &rand)
                coeffs[c] = rand
            }
            // Evaluate f(x) for x = 1..n
            for i in 0..<n {
                let x = UInt8(i + 1)
                var y: UInt8 = 0
                var xPow: UInt8 = 1
                for coeff in coeffs {
                    y ^= gfMul(coeff, xPow)
                    xPow = gfMul(xPow, x)
                }
                shareValues[i][byteIdx] = y
            }
        }
        return (0..<n).map { Share(id: UInt8($0 + 1), value: Data(shareValues[$0])) }
    }

    /// Reconstruct a secret from k or more shares using Lagrange interpolation in GF(256).
    public static func reconstructSecret(_ shares: [Share]) -> Data? {
        guard shares.count >= 2 else { return nil }
        let len = shares[0].value.count
        guard shares.allSatisfy({ $0.value.count == len }) else { return nil }

        var secret = [UInt8](repeating: 0, count: len)
        for byteIdx in 0..<len {
            // Lagrange interpolation at x=0
            var result: UInt8 = 0
            for i in 0..<shares.count {
                let xi = shares[i].id
                let yi = shares[i].value[byteIdx]
                var num: UInt8 = 1
                var den: UInt8 = 1
                for j in 0..<shares.count where i != j {
                    let xj = shares[j].id
                    // numerator: product of (0 - xj) = xj in GF(256)
                    num = gfMul(num, xj)
                    // denominator: product of (xi - xj) = xi XOR xj
                    den = gfMul(den, xi ^ xj)
                }
                result ^= gfMul(yi, gfMul(num, gfInverse(den)))
            }
            secret[byteIdx] = result
        }
        return Data(secret)
    }

    // MARK: - First-Message Encryption

    /// Encrypt data for a recipient using their X25519 public key.
    /// Uses ephemeral DH → HKDF → AES-256-GCM.
    /// Returns the encrypted payload and the ephemeral public key (which must be sent alongside).
    public static func encryptForRecipient(recipientX25519PublicKey: Data, plaintext: Data)
        -> (encrypted: EncryptedPayload, ephemeralPublicKey: Data) {
        let ephemeral = generateEphemeralX25519()
        let shared = deriveSharedSecret(myPrivate: ephemeral.privateKey, theirPublic: recipientX25519PublicKey)
        let key = hkdf(secret: shared, salt: Data("idap-first-msg-v1".utf8),
                       info: Data("first-message-encryption".utf8), length: 32)
        let encrypted = encrypt(key: key, plaintext: plaintext)
        return (encrypted, ephemeral.publicKey)
    }

    /// Decrypt data sent via first-message encryption.
    /// The sender's ephemeral public key must have been transmitted alongside the payload.
    public static func decryptFromSender(myX25519PrivateKey: Data, ephemeralPublicKey: Data,
        payload: EncryptedPayload) -> Data? {
        let shared = deriveSharedSecret(myPrivate: myX25519PrivateKey, theirPublic: ephemeralPublicKey)
        let key = hkdf(secret: shared, salt: Data("idap-first-msg-v1".utf8),
                       info: Data("first-message-encryption".utf8), length: 32)
        return decrypt(key: key, payload: payload)
    }

    // MARK: - Typed Key Derivation

    /// Derive a typed Ed25519 persona key pair at m/index'.
    public static func deriveTypedPersonaKey(seed: Data, index: UInt32) -> TypedKeyPair {
        let kp = derivePersonaKey(seed: seed, index: index)
        return TypedKeyPair(
            publicKey: TypedKey(kty: .ed25519, rawKey: kp.publicKey),
            privateKey: kp.privateKey
        )
    }

    /// Generate a typed X25519 key pair from a 32-byte seed.
    public static func generateTypedEphemeralX25519FromSeed(_ seed: Data) -> TypedKeyPair {
        let kp = generateEphemeralX25519FromSeed(seed)
        return TypedKeyPair(
            publicKey: TypedKey(kty: .x25519, rawKey: kp.publicKey),
            privateKey: kp.privateKey
        )
    }

    /// Generate a random typed X25519 key pair.
    public static func generateTypedEphemeralX25519() -> TypedKeyPair {
        let kp = generateEphemeralX25519()
        return TypedKeyPair(
            publicKey: TypedKey(kty: .x25519, rawKey: kp.publicKey),
            privateKey: kp.privateKey
        )
    }

    // MARK: - Private Helpers

    static func hmacSHA512(key: Data, data: Data) -> Data {
        let symKey = SymmetricKey(data: key)
        let mac = HMAC<SHA512>.authenticationCode(for: data, using: symKey)
        return Data(mac)
    }

    static func ser32(_ i: UInt32) -> Data {
        var out = Data(count: 4)
        out[0] = UInt8((i >> 24) & 0xFF)
        out[1] = UInt8((i >> 16) & 0xFF)
        out[2] = UInt8((i >> 8) & 0xFF)
        out[3] = UInt8(i & 0xFF)
        return out
    }
}
