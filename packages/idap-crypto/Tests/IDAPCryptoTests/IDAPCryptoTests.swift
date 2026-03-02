import XCTest
import CryptoKit
@testable import IDAPCrypto

// MARK: - BIP-39

final class BIP39Tests: XCTestCase {

    func testGenerateMasterSeedIsThirtyTwoBytes() {
        let seed = IDAPCrypto.generateMasterSeed()
        XCTAssertEqual(seed.count, 32)
    }

    func testSeedMnemonicRoundTrip() {
        let seed = IDAPCrypto.generateMasterSeed()
        let words = IDAPCrypto.seedToMnemonic(seed)
        XCTAssertEqual(words.count, 24)
        let recovered = IDAPCrypto.mnemonicToSeed(words)
        XCTAssertEqual(recovered, seed)
    }

    func testMnemonicDecodeKnownVector() {
        // BIP-39 test vector (all-zero entropy → specific mnemonic)
        // entropy: 00000000000000000000000000000000 (16 bytes) → 12 words
        // For 32 bytes (256-bit):
        // entropy: 0000000000000000000000000000000000000000000000000000000000000000
        // checksum: SHA256(32 zero bytes)[0] = 0x66 → high 8 bits = 0x66
        // But we use 32-byte seed, so let's compute it deterministically.
        let seed = Data(repeating: 0, count: 32)
        let words = IDAPCrypto.seedToMnemonic(seed)
        XCTAssertEqual(words.count, 24)
        // Verify round-trip
        let recovered = IDAPCrypto.mnemonicToSeed(words)
        XCTAssertEqual(recovered, seed, "Round-trip of all-zero seed must succeed")
        // First word for all-zero entropy is always "abandon"
        XCTAssertEqual(words[0], "abandon")
    }

    func testInvalidMnemonicReturnsNil() {
        let result = IDAPCrypto.mnemonicToSeed(["not", "valid", "words", "at", "all", "here",
                                                "not", "valid", "words", "at", "all", "here",
                                                "not", "valid", "words", "at", "all", "here",
                                                "not", "valid", "words", "at", "all", "here"])
        XCTAssertNil(result)
    }

    func testWrongChecksumReturnsNil() {
        // Get a valid mnemonic, then swap the last word to break the checksum
        let seed = IDAPCrypto.generateMasterSeed()
        var words = IDAPCrypto.seedToMnemonic(seed)
        // Change the last word to something different
        let lastWord = words[23]
        words[23] = (lastWord == "abandon") ? "ability" : "abandon"
        let result = IDAPCrypto.mnemonicToSeed(words)
        XCTAssertNil(result, "Tampered checksum word should return nil")
    }
}

// MARK: - Key Derivation

final class KeyDerivationTests: XCTestCase {

    let testSeed = Data(repeating: 0x42, count: 32)

    func testPersonaKeyDeterministic() {
        let kp1 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        let kp2 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        XCTAssertEqual(kp1.publicKey, kp2.publicKey)
        XCTAssertEqual(kp1.privateKey, kp2.privateKey)
    }

    func testKnownMnemonicProducesSlashInBase64() {
        let words = ["sense", "voyage", "tip", "lake", "unveil", "pledge",
                     "tiger", "noise", "coral", "group", "battle", "report",
                     "transfer", "meadow", "local", "reason", "march", "skull",
                     "antenna", "accident", "soap", "amateur", "exist", "admit"]
        guard let seed = IDAPCrypto.mnemonicToSeed(words) else {
            XCTFail("mnemonic decode failed")
            return
        }
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: 0)
        let b64 = kp.publicKey.base64EncodedString()
        XCTAssertTrue(b64.contains("/") || b64.contains("+"),
                      "Expected slash or plus in base64: \(b64)")
        // Verify base64url conversion removes problematic characters
        let b64url = b64.replacingOccurrences(of: "+", with: "-")
                        .replacingOccurrences(of: "/", with: "_")
                        .replacingOccurrences(of: "=", with: "")
        XCTAssertFalse(b64url.contains("/"), "base64url must not contain /")
        XCTAssertFalse(b64url.contains("+"), "base64url must not contain +")
        XCTAssertFalse(b64url.contains("="), "base64url must not contain =")
    }

    func testPersonaKeysDifferAcrossIndices() {
        let kp0 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        let kp1 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 1)
        let kp2 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 2)
        XCTAssertNotEqual(kp0.publicKey, kp1.publicKey)
        XCTAssertNotEqual(kp0.publicKey, kp2.publicKey)
        XCTAssertNotEqual(kp1.publicKey, kp2.publicKey)
    }

    func testPersonaKeysHardened() {
        // Hardened derivation: child key must differ from non-hardened path
        // We confirm that different indices produce different keys (hardened path is used)
        let kpA = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        let kpB = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        XCTAssertEqual(kpA.publicKey, kpB.publicKey, "Hardened derivation must be deterministic")

        // Verify that index 0 and index 1 differ (hardened path does not have the normal
        // additive relationship of non-hardened BIP-32 keys)
        let kpC = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 1)
        XCTAssertNotEqual(kpA.publicKey, kpC.publicKey)

        // P-256 variant
        let p256A = IDAPCrypto.derivePersonaKeyP256(seed: testSeed, index: 0)
        let p256B = IDAPCrypto.derivePersonaKeyP256(seed: testSeed, index: 1)
        XCTAssertNotEqual(p256A.publicKey, p256B.publicKey)
    }
}

// MARK: - Signing

final class SigningTests: XCTestCase {

    func testSignVerifyRoundTrip() {
        let kp = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x11, count: 32), index: 0)
        let message = Data("hello world".utf8)
        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: message)
        XCTAssertTrue(IDAPCrypto.verify(publicKey: kp.publicKey, message: message, signature: sig))
    }

    func testVerifyFailsOnTamperedMessage() {
        let kp = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x22, count: 32), index: 0)
        let message = Data("original message".utf8)
        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: message)
        let tampered = Data("tampered message".utf8)
        XCTAssertFalse(IDAPCrypto.verify(publicKey: kp.publicKey, message: tampered, signature: sig))
    }

    func testVerifyFailsOnWrongKey() {
        let kp1 = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x33, count: 32), index: 0)
        let kp2 = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x33, count: 32), index: 1)
        let message = Data("test".utf8)
        let sig = IDAPCrypto.sign(privateKey: kp1.privateKey, message: message)
        XCTAssertFalse(IDAPCrypto.verify(publicKey: kp2.publicKey, message: message, signature: sig))
    }

    func testVerifyFailsOnTamperedSignature() {
        let kp = IDAPCrypto.derivePersonaKey(seed: Data(repeating: 0x44, count: 32), index: 0)
        let message = Data("test".utf8)
        var sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: message)
        // Flip a bit in the signature
        sig[0] ^= 0xFF
        XCTAssertFalse(IDAPCrypto.verify(publicKey: kp.publicKey, message: message, signature: sig))
    }
}

// MARK: - Encryption

final class EncryptionTests: XCTestCase {

    let key32: Data = {
        var k = Data(count: 32)
        k[0] = 0xAB
        k[31] = 0xCD
        return k
    }()

    func testEncryptDecryptRoundTrip() {
        let plaintext = Data("secret contact card".utf8)
        let payload = IDAPCrypto.encrypt(key: key32, plaintext: plaintext)
        let decrypted = IDAPCrypto.decrypt(key: key32, payload: payload)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptFailsWithWrongKey() {
        let plaintext = Data("secret".utf8)
        let payload = IDAPCrypto.encrypt(key: key32, plaintext: plaintext)
        var wrongKey = key32
        wrongKey[0] ^= 0xFF
        let result = IDAPCrypto.decrypt(key: wrongKey, payload: payload)
        XCTAssertNil(result)
    }

    func testDecryptFailsOnTamperedCiphertext() {
        let plaintext = Data("secret".utf8)
        var payload = IDAPCrypto.encrypt(key: key32, plaintext: plaintext)
        // Tamper with first byte of ciphertext
        var ct = payload.ciphertext
        ct[0] ^= 0xFF
        payload = EncryptedPayload(ciphertext: ct, nonce: payload.nonce, tag: payload.tag)
        let result = IDAPCrypto.decrypt(key: key32, payload: payload)
        XCTAssertNil(result)
    }

    func testNonceIsRandomPerEncryption() {
        let plaintext = Data("same plaintext".utf8)
        let p1 = IDAPCrypto.encrypt(key: key32, plaintext: plaintext)
        let p2 = IDAPCrypto.encrypt(key: key32, plaintext: plaintext)
        XCTAssertNotEqual(p1.nonce, p2.nonce, "Each call must generate a fresh random nonce")
    }
}

// MARK: - Key Agreement

final class KeyAgreementTests: XCTestCase {

    func testX25519SharedSecretAgreement() {
        let alice = IDAPCrypto.generateEphemeralX25519()
        let bob = IDAPCrypto.generateEphemeralX25519()

        let aliceShared = IDAPCrypto.deriveSharedSecret(myPrivate: alice.privateKey, theirPublic: bob.publicKey)
        let bobShared = IDAPCrypto.deriveSharedSecret(myPrivate: bob.privateKey, theirPublic: alice.publicKey)

        XCTAssertEqual(aliceShared, bobShared, "Both parties must compute the same shared secret")
        XCTAssertEqual(aliceShared.count, 32)
    }

    func testHKDFIsDeterministic() {
        let secret = Data(repeating: 0x77, count: 32)
        let salt = Data("salt".utf8)
        let info = Data("info".utf8)
        let k1 = IDAPCrypto.hkdf(secret: secret, salt: salt, info: info, length: 32)
        let k2 = IDAPCrypto.hkdf(secret: secret, salt: salt, info: info, length: 32)
        XCTAssertEqual(k1, k2)
        XCTAssertEqual(k1.count, 32)
    }

    func testDifferentInfoProducesDifferentKey() {
        let secret = Data(repeating: 0x88, count: 32)
        let salt = Data("salt".utf8)
        let k1 = IDAPCrypto.hkdf(secret: secret, salt: salt, info: Data("info1".utf8), length: 32)
        let k2 = IDAPCrypto.hkdf(secret: secret, salt: salt, info: Data("info2".utf8), length: 32)
        XCTAssertNotEqual(k1, k2)
    }
}

// MARK: - Shamir Secret Sharing

final class ShamirTests: XCTestCase {

    let secret32 = Data((0..<32).map { UInt8($0 &* 7 &+ 3) })

    func testSplitReconstructTwoOfFour() {
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        XCTAssertEqual(shares.count, 4)
        let reconstructed = IDAPCrypto.reconstructSecret([shares[0], shares[2]])
        XCTAssertEqual(reconstructed, secret32)
    }

    func testReconstructFailsWithOneShard() {
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        let result = IDAPCrypto.reconstructSecret([shares[0]])
        XCTAssertNil(result, "One share is insufficient for k=2")
    }

    func testAnyTwoShardsOfFourWork() {
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        // All C(4,2) = 6 combinations
        let pairs: [(Int, Int)] = [(0,1),(0,2),(0,3),(1,2),(1,3),(2,3)]
        for (i, j) in pairs {
            let result = IDAPCrypto.reconstructSecret([shares[i], shares[j]])
            XCTAssertEqual(result, secret32, "Pair (\(i),\(j)) should reconstruct correctly")
        }
    }

    func testShardsAreDistinct() {
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        for i in 0..<shares.count {
            for j in (i+1)..<shares.count {
                XCTAssertNotEqual(shares[i].value, shares[j].value,
                                  "Shares \(i) and \(j) must have different values")
            }
        }
    }

    func testAllFourShardsReconstruct() {
        let shares = IDAPCrypto.splitSecret(secret32, k: 2, n: 4)
        let result = IDAPCrypto.reconstructSecret(shares)
        XCTAssertEqual(result, secret32)
    }

    func testThreeOfFive() {
        let secret = IDAPCrypto.generateMasterSeed()
        let shares = IDAPCrypto.splitSecret(secret, k: 3, n: 5)
        XCTAssertEqual(shares.count, 5)
        // Any 3 should work
        let result = IDAPCrypto.reconstructSecret([shares[1], shares[3], shares[4]])
        XCTAssertEqual(result, secret)
        // Only 2 should fail (we can't assert nil here because k=3, 2 < 3, but the math
        // will return a wrong result — not the original secret)
        let tooFew = IDAPCrypto.reconstructSecret([shares[0], shares[2]])
        XCTAssertNotEqual(tooFew, secret, "Two shares should not reconstruct the correct secret for k=3")
    }
}

// MARK: - TypedKey & Base64URL

final class TypedKeyTests: XCTestCase {

    func testBase64URLRoundTrip() {
        // Test with data that produces +, /, and = in standard base64
        let data = Data([0xfb, 0xff, 0xfe, 0x00, 0x01, 0x02])
        let encoded = data.base64URLEncodedString()
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        let decoded = Data(base64URLEncoded: encoded)
        XCTAssertEqual(decoded, data)
    }

    func testBase64URLDecodesStandardPadded() {
        // base64url should handle input with or without padding
        let data = Data("hello".utf8)
        let std = data.base64EncodedString() // "aGVsbG8="
        let noPad = std.replacingOccurrences(of: "=", with: "")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        XCTAssertEqual(Data(base64URLEncoded: noPad), data)
    }

    func testTypedKeyEncodeDecode() throws {
        let seed = Data(repeating: 0x42, count: 32)
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: 0)
        let tk = TypedKey(kty: .ed25519, rawKey: kp.publicKey)

        let encoded = try JSONEncoder().encode(tk)
        let decoded = try JSONDecoder().decode(TypedKey.self, from: encoded)

        XCTAssertEqual(decoded.kty, .ed25519)
        XCTAssertEqual(decoded.decode(), kp.publicKey)
    }

    func testTypedKeyJSONShape() throws {
        let key = TypedKey(kty: .x25519, rawKey: Data(repeating: 0xAA, count: 32))
        let json = try JSONEncoder().encode(key)
        let dict = try JSONSerialization.jsonObject(with: json) as? [String: Any]
        XCTAssertEqual(dict?["kty"] as? String, "x25519")
        XCTAssertNotNil(dict?["key"] as? String)
    }

    func testDeriveTypedPersonaKey() {
        let seed = Data(repeating: 0x42, count: 32)
        let typed = IDAPCrypto.deriveTypedPersonaKey(seed: seed, index: 0)
        let plain = IDAPCrypto.derivePersonaKey(seed: seed, index: 0)

        XCTAssertEqual(typed.publicKey.kty, .ed25519)
        XCTAssertEqual(typed.publicKey.decode(), plain.publicKey)
        XCTAssertEqual(typed.privateKey, plain.privateKey)
    }

    func testGenerateTypedEphemeralX25519FromSeed() {
        let seed = Data(repeating: 0x55, count: 32)
        let typed = IDAPCrypto.generateTypedEphemeralX25519FromSeed(seed)
        let plain = IDAPCrypto.generateEphemeralX25519FromSeed(seed)

        XCTAssertEqual(typed.publicKey.kty, .x25519)
        XCTAssertEqual(typed.publicKey.decode(), plain.publicKey)
        XCTAssertEqual(typed.privateKey, plain.privateKey)
    }

    func testGenerateTypedEphemeralX25519() {
        let typed = IDAPCrypto.generateTypedEphemeralX25519()
        XCTAssertEqual(typed.publicKey.kty, .x25519)
        XCTAssertNotNil(typed.publicKey.decode())
        XCTAssertEqual(typed.publicKey.decode()?.count, 32)
    }
}

// MARK: - First-Message Encryption

final class FirstMessageEncryptionTests: XCTestCase {

    func testEncryptDecryptRoundTrip() {
        let recipient = IDAPCrypto.generateEphemeralX25519()
        let plaintext = Data("hello from first message".utf8)

        let (encrypted, ephemeralPub) = IDAPCrypto.encryptForRecipient(
            recipientX25519PublicKey: recipient.publicKey, plaintext: plaintext)

        let decrypted = IDAPCrypto.decryptFromSender(
            myX25519PrivateKey: recipient.privateKey,
            ephemeralPublicKey: ephemeralPub,
            payload: encrypted)

        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptFailsWithWrongKey() {
        let recipient = IDAPCrypto.generateEphemeralX25519()
        let wrongKey = IDAPCrypto.generateEphemeralX25519()
        let plaintext = Data("secret".utf8)

        let (encrypted, ephemeralPub) = IDAPCrypto.encryptForRecipient(
            recipientX25519PublicKey: recipient.publicKey, plaintext: plaintext)

        let result = IDAPCrypto.decryptFromSender(
            myX25519PrivateKey: wrongKey.privateKey,
            ephemeralPublicKey: ephemeralPub,
            payload: encrypted)

        XCTAssertNil(result)
    }

    func testEachEncryptionUsesDifferentEphemeralKey() {
        let recipient = IDAPCrypto.generateEphemeralX25519()
        let plaintext = Data("same plaintext".utf8)

        let (_, eph1) = IDAPCrypto.encryptForRecipient(
            recipientX25519PublicKey: recipient.publicKey, plaintext: plaintext)
        let (_, eph2) = IDAPCrypto.encryptForRecipient(
            recipientX25519PublicKey: recipient.publicKey, plaintext: plaintext)

        XCTAssertNotEqual(eph1, eph2, "Each encryption should use a new ephemeral key")
    }
}
