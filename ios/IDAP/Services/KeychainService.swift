import Foundation
import Security

enum KeychainError: Error {
    case unhandledError(OSStatus)
    case unexpectedData
}

final class KeychainService: KeychainProviding {
    private let accessGroup = "app.idap"

    func saveSeedCiphertext(_ data: Data) throws {
        try save(data, forKey: "idap.seedCiphertext")
    }

    func loadSeedCiphertext() throws -> Data? {
        try load(forKey: "idap.seedCiphertext")
    }

    func deleteAll() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "idap.seedCiphertext"
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status)
        }
    }

    // MARK: - Private helpers

    private func save(_ data: Data, forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status)
        }
    }

    private func load(forKey key: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status)
        }
        guard let data = result as? Data else {
            throw KeychainError.unexpectedData
        }
        return data
    }
}
