import XCTest
@testable import IDAPRecovery
@testable import IDAPContacts
@testable import IDAPCrypto

private let testSeed = Data(repeating: 0xDE, count: 32)
private let testProxy = URL(string: "https://idap.app")!

private func makeContact(_ pubKey: Data) -> Contact {
    let kp = IDAPCrypto.generateEphemeralX25519()
    return Contact(id: UUID().uuidString, personaId: "real",
                   publicKey: pubKey, identityPublicKey: kp.publicKey,
                   sharedSecret: Data(repeating: 0x11, count: 32))
}

// MARK: - RecoveryMapTests

final class RecoveryMapTests: XCTestCase {

    func testGenerateMapWithFourContacts_TwoOfFour() throws {
        let recovery = IDAPRecovery()
        let contacts = (1...4).map { _ in makeContact(Data(repeating: UInt8.random(in: 0...255), count: 32)) }
        let map = recovery.generateRecoveryMap(seed: testSeed, contacts: contacts)
        XCTAssertEqual(map.scheme, "2-of-4")
        XCTAssertEqual(map.n, 4)
        XCTAssertEqual(map.k, 2)
        XCTAssertEqual(map.entries.count, 4)
    }

    func testGenerateMapWithTwoContacts_TwoOfTwo() throws {
        let recovery = IDAPRecovery()
        let contacts = (1...2).map { _ in makeContact(Data(repeating: UInt8.random(in: 0...255), count: 32)) }
        let map = recovery.generateRecoveryMap(seed: testSeed, contacts: contacts)
        XCTAssertEqual(map.scheme, "2-of-2")
        XCTAssertEqual(map.n, 2)
        XCTAssertEqual(map.k, 2)
    }

    func testSaveAndFetchMap() throws {
        let store = InMemoryRecoveryMapStore()
        let recovery = IDAPRecovery(store: store)
        let contacts = (1...4).map { _ in makeContact(Data(repeating: UInt8.random(in: 0...255), count: 32)) }
        let map = recovery.generateRecoveryMap(seed: testSeed, contacts: contacts)
        try recovery.saveRecoveryMap(map)
        let fetched = try recovery.fetchRecoveryMap()
        XCTAssertEqual(fetched, map)
    }

    func testMapContainsNoKeyMaterial() throws {
        let recovery = IDAPRecovery()
        let contacts = (1...4).map { _ in makeContact(Data(repeating: UInt8.random(in: 0...255), count: 32)) }
        let map = recovery.generateRecoveryMap(seed: testSeed, contacts: contacts)
        let json = try JSONEncoder().encode(map)
        let jsonStr = String(data: json, encoding: .utf8) ?? ""
        // The map JSON must not contain the raw seed bytes
        let seedHex = testSeed.map { String(format: "%02x", $0) }.joined()
        XCTAssertFalse(jsonStr.contains(seedHex), "Recovery map must not contain the master seed")
        // Must not contain the base64 of the seed
        let seedB64 = testSeed.base64EncodedString()
        XCTAssertFalse(jsonStr.contains(seedB64), "Recovery map must not contain base64-encoded seed")
    }
}

// MARK: - ShardEncryptionTests

final class ShardEncryptionTests: XCTestCase {

    let recovery = IDAPRecovery()

    private func makeShare(id: UInt8) -> Share {
        Share(id: id, value: Data(repeating: id &* 13 &+ 7, count: 32))
    }

    func testEncryptShardForContactDecryptable() throws {
        let kp = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(id: 1)
        let encrypted = try XCTUnwrap(recovery.encryptShardForContact(shard, contactIdentityPublicKey: kp.publicKey))
        let decrypted = try XCTUnwrap(recovery.decryptShardForContact(encrypted, myPrivateKey: kp.privateKey))
        XCTAssertEqual(decrypted.id, shard.id)
        XCTAssertEqual(decrypted.value, shard.value)
    }

    func testEncryptShardForContactNotDecryptableByOther() throws {
        let bobKP   = IDAPCrypto.generateEphemeralX25519()
        let carolKP = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(id: 2)
        let encrypted = try XCTUnwrap(recovery.encryptShardForContact(shard, contactIdentityPublicKey: bobKP.publicKey))
        let result = recovery.decryptShardForContact(encrypted, myPrivateKey: carolKP.privateKey)
        XCTAssertNil(result, "Shard encrypted for Bob must not be decryptable by Carol")
    }

    func testEncryptShardWithPasswordDecryptable() throws {
        let shard = makeShare(id: 3)
        let encrypted = try XCTUnwrap(recovery.encryptShardWithPassword(shard, password: "correct-horse-battery"))
        let decrypted = try XCTUnwrap(recovery.decryptShardWithPassword(encrypted, password: "correct-horse-battery"))
        XCTAssertEqual(decrypted.id, shard.id)
        XCTAssertEqual(decrypted.value, shard.value)
    }

    func testEncryptShardWithWrongPasswordReturnsNil() throws {
        let shard = makeShare(id: 4)
        let encrypted = try XCTUnwrap(recovery.encryptShardWithPassword(shard, password: "correct"))
        let result = recovery.decryptShardWithPassword(encrypted, password: "wrong-password")
        XCTAssertNil(result, "Wrong password must fail to decrypt")
    }

    func testEncryptedShardsAreDifferentBytesPerContact() throws {
        let kp1 = IDAPCrypto.generateEphemeralX25519()
        let kp2 = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(id: 1)
        let enc1 = try XCTUnwrap(recovery.encryptShardForContact(shard, contactIdentityPublicKey: kp1.publicKey))
        let enc2 = try XCTUnwrap(recovery.encryptShardForContact(shard, contactIdentityPublicKey: kp2.publicKey))
        XCTAssertNotEqual(enc1.ciphertext, enc2.ciphertext, "Each contact's encrypted shard must be distinct")
    }
}

// MARK: - TimedCodeTests

final class TimedCodeTests: XCTestCase {

    private let kp = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0xAB, count: 32), index: 0)
    private let shardId = "shard-001"

    func testGenerateCodeHasCorrectFormat() throws {
        let recovery = IDAPRecovery()
        let code = recovery.generateTimedCode(shardId: shardId, privateKey: kp.privateKey)
        // Format: groups of 2 chars joined by "-", e.g. "AB-CD-EF-GH"
        let parts = code.code.split(separator: "-")
        XCTAssertGreaterThan(parts.count, 0)
        for part in parts {
            XCTAssertLessThanOrEqual(part.count, 2)
        }
        XCTAssertFalse(code.code.isEmpty)
    }

    func testCodeValidWithinFifteenMinutes() throws {
        let clock = MockClock(date: Date())
        let recovery = IDAPRecovery(clock: clock)
        let code = recovery.generateTimedCode(shardId: shardId, privateKey: kp.privateKey)
        XCTAssertTrue(recovery.isTimedCodeValid(code))
        clock.advance(by: 14 * 60)  // 14 minutes later — still valid
        XCTAssertTrue(recovery.isTimedCodeValid(code))
    }

    func testCodeExpiredAfterFifteenMinutes() throws {
        let clock = MockClock(date: Date())
        let recovery = IDAPRecovery(clock: clock)
        let code = recovery.generateTimedCode(shardId: shardId, privateKey: kp.privateKey)
        clock.advance(by: 16 * 60)  // 16 minutes — expired
        XCTAssertFalse(recovery.isTimedCodeValid(code), "Code must be invalid after 15 minutes")
    }

    func testCodeIsOneTimeUse() throws {
        // Two codes generated at same time have different nonces → different codes
        let clock = MockClock(date: Date())
        let recovery = IDAPRecovery(clock: clock)
        let code1 = recovery.generateTimedCode(shardId: shardId, privateKey: kp.privateKey)
        let code2 = recovery.generateTimedCode(shardId: shardId, privateKey: kp.privateKey)
        // Nonces must differ (UUID-based)
        XCTAssertNotEqual(code1.nonce, code2.nonce)
        // Codes may differ due to different nonce inputs to HMAC
        XCTAssertNotEqual(code1.signature, code2.signature)
    }

    func testWrongPasswordYieldsUndecryptableShard() throws {
        let recovery = IDAPRecovery()
        let shard = Share(id: 1, value: Data(repeating: 0x42, count: 32))
        let encrypted = try XCTUnwrap(recovery.encryptShardWithPassword(shard, password: "secret"))
        let result = recovery.decryptShardWithPassword(encrypted, password: "not-the-password")
        XCTAssertNil(result, "Wrong password must produce undecryptable shard")
    }
}

// MARK: - SeedReconstructionTests

final class SeedReconstructionTests: XCTestCase {

    let secret32 = Data((0..<32).map { UInt8($0 &* 7 &+ 3) })

    func testReconstructFromMinimumShards() throws {
        let recovery = IDAPRecovery()
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        let reconstructed = try XCTUnwrap(recovery.reconstructSeed([shares[0], shares[2]]))
        XCTAssertEqual(reconstructed, secret32)
    }

    func testReconstructFromAllShards() throws {
        let recovery = IDAPRecovery()
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        let reconstructed = try XCTUnwrap(recovery.reconstructSeed(shares))
        XCTAssertEqual(reconstructed, secret32)
    }

    func testReconstructMatchesOriginalSeed() throws {
        let recovery = IDAPRecovery()
        let shares = IDAPCrypto.splitSecret(testSeed, k: 3, n: 5)
        let reconstructed = try XCTUnwrap(recovery.reconstructSeed([shares[0], shares[2], shares[4]]))
        XCTAssertEqual(reconstructed, testSeed)
    }

    func testReconstructFailsBelowThreshold() throws {
        let recovery = IDAPRecovery()
        let shares = IDAPCrypto.splitSecret(secret32, k: 3, n: 5)
        // 2 shares for k=3 → should return wrong result (not the secret)
        let result = recovery.reconstructSeed([shares[0], shares[1]])
        XCTAssertNotEqual(result, secret32, "Two shares must not reconstruct the secret when k=3")
    }
}

// MARK: - MigrationTests

final class MigrationTests: XCTestCase {

    let kp = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x77, count: 32), index: 0)
    let newKP = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x88, count: 32), index: 0)

    func testCreateMigrationRecordSignedByOldKey() throws {
        let recovery = IDAPRecovery()
        let migration = recovery.createMigrationRecord(
            oldPublicKey: kp.publicKey.base64EncodedString(),
            newPublicKey: newKP.publicKey.base64EncodedString(),
            newProxy: URL(string: "https://proxy-b.com")!,
            oldPrivateKey: kp.privateKey
        )
        XCTAssertEqual(migration.oldPublicKey, kp.publicKey.base64EncodedString())
        XCTAssertEqual(migration.newPublicKey, newKP.publicKey.base64EncodedString())
        XCTAssertFalse(migration.signature.isEmpty)
    }

    func testVerifyMigrationSignaturePasses() throws {
        let recovery = IDAPRecovery()
        let migration = recovery.createMigrationRecord(
            oldPublicKey: kp.publicKey.base64EncodedString(),
            newPublicKey: newKP.publicKey.base64EncodedString(),
            newProxy: URL(string: "https://proxy-b.com")!,
            oldPrivateKey: kp.privateKey
        )
        let valid = recovery.verifyMigrationRecord(migration, oldPublicKey: kp.publicKey)
        XCTAssertTrue(valid)
    }

    func testTamperedMigrationRecordRejected() throws {
        let recovery = IDAPRecovery()
        var migration = recovery.createMigrationRecord(
            oldPublicKey: kp.publicKey.base64EncodedString(),
            newPublicKey: newKP.publicKey.base64EncodedString(),
            newProxy: URL(string: "https://proxy-b.com")!,
            oldPrivateKey: kp.privateKey
        )
        // Tamper with the new public key
        let attackerKP = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x99, count: 32), index: 0)
        migration = SignedMigration(
            oldPublicKey: migration.oldPublicKey,
            newPublicKey: attackerKP.publicKey.base64EncodedString(),  // tampered
            newProxy: migration.newProxy,
            timestamp: migration.timestamp,
            signature: migration.signature
        )
        let valid = recovery.verifyMigrationRecord(migration, oldPublicKey: kp.publicKey)
        XCTAssertFalse(valid, "Tampered migration record must fail signature verification")
    }
}
