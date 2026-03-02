import Foundation
import IDAPCrypto

protocol CryptoProviding {
    func generateMasterSeed() -> Data
    func seedToMnemonic(_ seed: Data) -> [String]
    func mnemonicToSeed(_ words: [String]) -> Data?
    func generateEnclaveKey(label: String) -> Data?
    func enclaveEncrypt(label: String, data: Data) -> Data?
    func enclaveDecrypt(label: String, ciphertext: Data) -> Data?
    func encrypt(key: Data, plaintext: Data) -> EncryptedPayload
    func decrypt(key: Data, payload: EncryptedPayload) -> Data?
    func hkdf(secret: Data, salt: Data, info: Data, length: Int) -> Data
}
