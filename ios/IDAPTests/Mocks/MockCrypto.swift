import Foundation
import IDAPCrypto
@testable import IDAP

final class MockCrypto: CryptoProviding {
    var mockSeed: Data = Data(repeating: 0x42, count: 32)
    var mockMnemonic: [String] = Array(repeating: "word", count: 24)
    var mockEnclaveCiphertext: Data? = Data(repeating: 0xAB, count: 64)
    var generateSeedCalled: Bool = false
    var enclaveCalled: Bool = false
    var encryptCalled: Bool = false

    func generateMasterSeed() -> Data {
        generateSeedCalled = true
        return mockSeed
    }

    func seedToMnemonic(_ seed: Data) -> [String] { mockMnemonic }

    func mnemonicToSeed(_ words: [String]) -> Data? {
        words.count == 24 ? mockSeed : nil
    }

    func generateEnclaveKey(label: String) -> Data? {
        enclaveCalled = true
        return mockEnclaveCiphertext != nil ? Data(repeating: 0, count: 32) : nil
    }

    func enclaveEncrypt(label: String, data: Data) -> Data? {
        mockEnclaveCiphertext
    }

    func enclaveDecrypt(label: String, ciphertext: Data) -> Data? {
        ciphertext == mockEnclaveCiphertext ? mockSeed : nil
    }

    func encrypt(key: Data, plaintext: Data) -> EncryptedPayload {
        encryptCalled = true
        return EncryptedPayload(
            ciphertext: plaintext,
            nonce: Data(repeating: 0, count: 12),
            tag: Data(repeating: 0, count: 16)
        )
    }

    func decrypt(key: Data, payload: EncryptedPayload) -> Data? {
        payload.ciphertext
    }

    func hkdf(secret: Data, salt: Data, info: Data, length: Int) -> Data {
        Data(repeating: 0x11, count: length)
    }
}
