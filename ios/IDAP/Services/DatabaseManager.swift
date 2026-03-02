import Foundation
import GRDB
import IDAPRecovery

final class DatabaseManager {
    static let shared = DatabaseManager()

    private let appSupportDir: URL

    private init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("IDAP")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.appSupportDir = dir
    }

    lazy var identityQueue: DatabaseQueue = {
        try! DatabaseQueue(path: appSupportDir.appendingPathComponent("identity.db").path)
    }()

    lazy var authQueue: DatabaseQueue = {
        try! DatabaseQueue(path: appSupportDir.appendingPathComponent("auth.db").path)
    }()

    lazy var contactsQueue: DatabaseQueue = {
        try! DatabaseQueue(path: appSupportDir.appendingPathComponent("contacts.db").path)
    }()

    lazy var recoveryMapStore: JSONRecoveryMapStore = {
        JSONRecoveryMapStore(fileURL: appSupportDir.appendingPathComponent("recovery_map.json"))
    }()
}
