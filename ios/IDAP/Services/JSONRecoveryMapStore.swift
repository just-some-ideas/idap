import Foundation
import IDAPRecovery

final class JSONRecoveryMapStore: RecoveryMapStore {
    private let fileURL: URL

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    func save(_ map: RecoveryMap) throws {
        let data = try JSONEncoder().encode(map)
        try data.write(to: fileURL, options: .atomic)
    }

    func fetch() throws -> RecoveryMap? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        let data = try Data(contentsOf: fileURL)
        return try JSONDecoder().decode(RecoveryMap.self, from: data)
    }
}
