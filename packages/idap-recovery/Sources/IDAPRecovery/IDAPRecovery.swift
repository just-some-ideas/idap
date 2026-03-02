// IDAPRecovery — recovery map, shard encryption, timed codes, seed reconstruction, key migration
// Depends on: IDAPCrypto, IDAPContacts

import CryptoKit
import Foundation
import IDAPContacts
import IDAPCrypto

// MARK: - Clock Protocol (injectable for tests)

public protocol ClockProtocol {
    var now: Date { get }
}

public struct SystemClock: ClockProtocol {
    public init() {}
    public var now: Date { Date() }
}

public final class MockClock: ClockProtocol {
    public var currentDate: Date
    public var now: Date { currentDate }
    public init(date: Date = Date()) { self.currentDate = date }
    public func advance(by interval: TimeInterval) { currentDate.addTimeInterval(interval) }
}

// MARK: - Recovery Map

public struct ShardEntry: Codable, Equatable {
    public let shardId: String
    public let holderKey: String   // base64-encoded public key of the shard holder
    public let method: String      // "contact" or "proxy"

    public init(shardId: String, holderKey: String, method: String) {
        self.shardId = shardId; self.holderKey = holderKey; self.method = method
    }
}

public struct RecoveryMap: Codable, Equatable {
    public let scheme: String   // e.g. "2-of-4"
    public let entries: [ShardEntry]

    public init(scheme: String, entries: [ShardEntry]) {
        self.scheme = scheme; self.entries = entries
    }

    public var k: Int {
        Int(scheme.split(separator: "-").first.flatMap { Int($0) } ?? 2)
    }
    public var n: Int { entries.count }
}

// MARK: - Recovery Map Store Protocol

public protocol RecoveryMapStore {
    func save(_ map: RecoveryMap) throws
    func fetch() throws -> RecoveryMap?
}

public final class InMemoryRecoveryMapStore: RecoveryMapStore {
    private var stored: RecoveryMap?
    public init() {}
    public func save(_ map: RecoveryMap) throws { stored = map }
    public func fetch() throws -> RecoveryMap? { stored }
}

// MARK: - Shard Encryption Payloads

public struct EncryptedContactShard: Codable, Equatable {
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public let ephemeralPublicKey: Data

    public init(ciphertext: Data, nonce: Data, tag: Data, ephemeralPublicKey: Data) {
        self.ciphertext = ciphertext; self.nonce = nonce
        self.tag = tag; self.ephemeralPublicKey = ephemeralPublicKey
    }
}

public struct EncryptedPasswordShard: Codable, Equatable {
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public let salt: Data

    public init(ciphertext: Data, nonce: Data, tag: Data, salt: Data) {
        self.ciphertext = ciphertext; self.nonce = nonce; self.tag = tag; self.salt = salt
    }
}

// MARK: - Timed Code

public struct TimedCode: Equatable {
    public let code: String      // e.g. "AB-CD-EF-GH"
    public let shardId: String
    public let expiresAt: Date
    public let nonce: String
    public let signature: Data   // full HMAC-SHA256, for local verification

    public init(code: String, shardId: String, expiresAt: Date, nonce: String, signature: Data) {
        self.code = code; self.shardId = shardId; self.expiresAt = expiresAt
        self.nonce = nonce; self.signature = signature
    }
}

// MARK: - Signed Migration

public struct SignedMigration: Codable, Equatable {
    public let oldPublicKey: String   // base64-encoded old public key
    public let newPublicKey: String   // base64-encoded new public key
    public let newProxy: String       // URL as string for Codable simplicity
    public let timestamp: String      // ISO8601 date string
    public let signature: Data        // Ed25519 sig of canonical JSON

    public init(oldPublicKey: String, newPublicKey: String, newProxy: String,
                timestamp: String, signature: Data) {
        self.oldPublicKey = oldPublicKey; self.newPublicKey = newPublicKey; self.newProxy = newProxy
        self.timestamp = timestamp; self.signature = signature
    }
}

// MARK: - IDAPRecovery

public final class IDAPRecovery {

    private let store: RecoveryMapStore
    public let clock: ClockProtocol

    public init(store: RecoveryMapStore = InMemoryRecoveryMapStore(),
                clock: ClockProtocol = SystemClock()) {
        self.store = store
        self.clock = clock
    }

    // MARK: - Recovery Map

    /// Generate a recovery map distributing shards to the given contacts.
    /// Uses 2-of-4 if 4+ contacts, 2-of-3 if 3 contacts, 2-of-2 if 2, 1-of-1 if fewer.
    public func generateRecoveryMap(seed: Data, contacts: [Contact]) -> RecoveryMap {
        let n = min(contacts.count, 4)
        let k = max(1, min(2, n))
        let scheme = "\(k)-of-\(n)"

        let shares = IDAPCrypto.splitSecret(seed, k: k, n: n)
        let entries = shares.enumerated().map { (i, share) in
            ShardEntry(shardId: share.id.description + "-" + share.value.prefix(4).map { String(format: "%02x", $0) }.joined(),
                       holderKey: i < contacts.count ? contacts[i].publicKey.base64EncodedString() : "self",
                       method: "contact")
        }
        return RecoveryMap(scheme: scheme, entries: entries)
    }

    public func saveRecoveryMap(_ map: RecoveryMap) throws {
        try store.save(map)
    }

    public func fetchRecoveryMap() throws -> RecoveryMap? {
        try store.fetch()
    }

    // MARK: - Shard Encryption (Contact-based: X25519 + AES-GCM)

    public func encryptShardForContact(_ shard: Share, contactIdentityPublicKey: Data) -> EncryptedContactShard? {
        let ephemeral = IDAPCrypto.generateEphemeralX25519()
        let dh = IDAPCrypto.deriveSharedSecret(myPrivate: ephemeral.privateKey,
                                               theirPublic: contactIdentityPublicKey)
        let key = IDAPCrypto.hkdf(secret: dh, salt: Data("idap-recovery-shard-v1".utf8),
                                   info: Data("shard-for-contact".utf8), length: 32)
        let plaintext = Data([shard.id]) + shard.value
        let payload = IDAPCrypto.encrypt(key: key, plaintext: plaintext)
        return EncryptedContactShard(ciphertext: payload.ciphertext, nonce: payload.nonce,
                                     tag: payload.tag, ephemeralPublicKey: ephemeral.publicKey)
    }

    public func decryptShardForContact(_ encrypted: EncryptedContactShard, myPrivateKey: Data) -> Share? {
        let dh = IDAPCrypto.deriveSharedSecret(myPrivate: myPrivateKey,
                                               theirPublic: encrypted.ephemeralPublicKey)
        let key = IDAPCrypto.hkdf(secret: dh, salt: Data("idap-recovery-shard-v1".utf8),
                                   info: Data("shard-for-contact".utf8), length: 32)
        let ep = EncryptedPayload(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce, tag: encrypted.tag)
        guard let plaintext = IDAPCrypto.decrypt(key: key, payload: ep),
              plaintext.count >= 1 else { return nil }
        return Share(id: plaintext[0], value: Data(plaintext[1...]))
    }

    // MARK: - Shard Encryption (Password-based: HKDF + AES-GCM)
    // Note: production should use Argon2id; HKDF is used here as a platform-native substitute.

    public func encryptShardWithPassword(_ shard: Share, password: String) -> EncryptedPasswordShard? {
        var saltBytes = Data(count: 32)
        _ = saltBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let key = deriveKeyFromPassword(password, salt: saltBytes)
        let plaintext = Data([shard.id]) + shard.value
        let payload = IDAPCrypto.encrypt(key: key, plaintext: plaintext)
        return EncryptedPasswordShard(ciphertext: payload.ciphertext, nonce: payload.nonce,
                                      tag: payload.tag, salt: saltBytes)
    }

    public func decryptShardWithPassword(_ encrypted: EncryptedPasswordShard, password: String) -> Share? {
        let key = deriveKeyFromPassword(password, salt: encrypted.salt)
        let ep = EncryptedPayload(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce, tag: encrypted.tag)
        guard let plaintext = IDAPCrypto.decrypt(key: key, payload: ep),
              plaintext.count >= 1 else { return nil }
        return Share(id: plaintext[0], value: Data(plaintext[1...]))
    }

    private func deriveKeyFromPassword(_ password: String, salt: Data) -> Data {
        // HKDF with password bytes as IKM and the random salt
        let pwData = Data(password.utf8)
        // Mix password + salt as the IKM for uniqueness
        return IDAPCrypto.hkdf(secret: pwData + salt, salt: Data("idap-password-kdf-v1".utf8),
                                info: Data("shard-password-key".utf8), length: 32)
    }

    // MARK: - Timed Code Generation & Verification

    /// Generate a 15-minute timed code for retrieving a shard.
    /// The private key is the persona's Ed25519 private key (used as HMAC key).
    public func generateTimedCode(shardId: String, privateKey: Data) -> TimedCode {
        let nonce = UUID().uuidString
        let expiresAt = clock.now.addingTimeInterval(15 * 60)
        let timestamp = String(Int(clock.now.timeIntervalSince1970))

        // HMAC-SHA256(shardId + ":" + timestamp + ":" + nonce, key: privateKey)
        let message = Data((shardId + ":" + timestamp + ":" + nonce).utf8)
        let hmacKey = SymmetricKey(data: privateKey)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: hmacKey)
        let macData = Data(mac)

        // Take first 5 bytes → encode in Crockford base32 → format "XX-XX-XX"
        let codeStr = crockfordBase32(macData.prefix(5))
        let code = formatCode(codeStr)

        return TimedCode(code: code, shardId: shardId, expiresAt: expiresAt,
                         nonce: nonce, signature: macData)
    }

    /// Verify a timed code has not expired (clock-injectable for tests).
    public func isTimedCodeValid(_ code: TimedCode) -> Bool {
        clock.now < code.expiresAt
    }

    // MARK: - Crockford Base32 (RFC 4648 variant without padding, uppercase)

    private static let crockfordAlphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    private func crockfordBase32(_ data: Data) -> String {
        // Encode 5 bytes (40 bits) as 8 Crockford base32 chars (5 bits each)
        var bits: UInt64 = 0
        for byte in data.prefix(5) {
            bits = (bits << 8) | UInt64(byte)
        }
        // Pad to 40 bits
        bits <<= UInt64(max(0, 40 - data.count * 8))
        var result = ""
        // 8 groups of 5 bits from the top
        let count = min(8, Int(ceil(Double(data.count * 8) / 5.0)))
        for i in (0..<count).reversed() {
            let idx = Int((bits >> (UInt64(i) * 5)) & 0x1F)
            result.append(IDAPRecovery.crockfordAlphabet[idx])
        }
        return result
    }

    private func formatCode(_ s: String) -> String {
        // Format as "XX-XX-XX-XX" (groups of 2)
        let chars = Array(s)
        var groups: [String] = []
        var i = 0
        while i < chars.count {
            let end = min(i + 2, chars.count)
            groups.append(String(chars[i..<end]))
            i += 2
        }
        return groups.joined(separator: "-")
    }

    // MARK: - Seed Reconstruction

    /// Reconstruct the master seed from k-of-n Shamir shares.
    public func reconstructSeed(_ shares: [Share]) -> Data? {
        IDAPCrypto.reconstructSecret(shares)
    }

    // MARK: - Key Migration

    /// Create a migration record signed by the old persona's private key.
    public func createMigrationRecord(
        oldPublicKey: String,
        newPublicKey: String,
        newProxy: URL,
        oldPrivateKey: Data
    ) -> SignedMigration {
        let timestamp = ISO8601DateFormatter().string(from: clock.now)
        let canonical = canonicalJSON([
            "newProxy": newProxy.absoluteString,
            "newPublicKey": newPublicKey,
            "oldPublicKey": oldPublicKey,
            "timestamp": timestamp,
        ])
        let sig = IDAPCrypto.sign(privateKey: oldPrivateKey, message: Data(canonical.utf8))
        return SignedMigration(oldPublicKey: oldPublicKey, newPublicKey: newPublicKey,
                               newProxy: newProxy.absoluteString,
                               timestamp: timestamp, signature: sig)
    }

    /// Verify the migration record's signature using the old persona's public key.
    public func verifyMigrationRecord(_ migration: SignedMigration, oldPublicKey: Data) -> Bool {
        let canonical = canonicalJSON([
            "newProxy": migration.newProxy,
            "newPublicKey": migration.newPublicKey,
            "oldPublicKey": migration.oldPublicKey,
            "timestamp": migration.timestamp,
        ])
        return IDAPCrypto.verify(publicKey: oldPublicKey,
                                 message: Data(canonical.utf8),
                                 signature: migration.signature)
    }

    // MARK: - Canonical JSON

    private func canonicalJSON(_ dict: [String: String]) -> String {
        let pairs = dict.keys.sorted().map { "\"\($0)\":\"\(dict[$0]!)\"" }.joined(separator: ",")
        return "{\(pairs)}"
    }
}
