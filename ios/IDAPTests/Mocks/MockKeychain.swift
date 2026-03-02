import Foundation
@testable import IDAP

final class MockKeychain: KeychainProviding {
    private var storage: [String: Data] = [:]
    var saveCalledFor: [String] = []
    var deleteAllCalled: Bool = false

    func saveSeedCiphertext(_ data: Data) throws {
        saveCalledFor.append("seedCiphertext")
        storage["seedCiphertext"] = data
    }

    func loadSeedCiphertext() throws -> Data? { storage["seedCiphertext"] }

    func deleteAll() throws {
        deleteAllCalled = true
        storage.removeAll()
    }
}
