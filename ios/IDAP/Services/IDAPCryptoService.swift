import Foundation
import IDAPCrypto

/// Wraps IDAPCrypto static functions behind the CryptoProviding protocol for testability.
final class IDAPCryptoService: CryptoProviding {
    func generateMasterSeed() -> Data {
        IDAPCrypto.generateMasterSeed()
    }

    func seedToMnemonic(_ seed: Data) -> [String] {
        IDAPCrypto.seedToMnemonic(seed)
    }

    func mnemonicToSeed(_ words: [String]) -> Data? {
        IDAPCrypto.mnemonicToSeed(words)
    }

    func generateEnclaveKey(label: String) -> Data? {
        IDAPCrypto.generateEnclaveKey(label: label)
    }

    func enclaveEncrypt(label: String, data: Data) -> Data? {
        IDAPCrypto.enclaveEncrypt(label: label, data: data)
    }

    func enclaveDecrypt(label: String, ciphertext: Data) -> Data? {
        IDAPCrypto.enclaveDecrypt(label: label, ciphertext: ciphertext)
    }

    func encrypt(key: Data, plaintext: Data) -> EncryptedPayload {
        IDAPCrypto.encrypt(key: key, plaintext: plaintext)
    }

    func decrypt(key: Data, payload: EncryptedPayload) -> Data? {
        IDAPCrypto.decrypt(key: key, payload: payload)
    }

    func hkdf(secret: Data, salt: Data, info: Data, length: Int) -> Data {
        IDAPCrypto.hkdf(secret: secret, salt: salt, info: info, length: length)
    }
}
