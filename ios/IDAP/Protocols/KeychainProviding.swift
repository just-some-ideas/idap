import Foundation

protocol KeychainProviding {
    func saveSeedCiphertext(_ data: Data) throws
    func loadSeedCiphertext() throws -> Data?
    func deleteAll() throws
}
