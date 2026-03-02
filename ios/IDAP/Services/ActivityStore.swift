import Foundation

struct ActivityEvent: Codable, Identifiable {
    let id: UUID
    let personaId: String
    let personaLabel: String
    let serviceName: String
    let timestamp: Date
    let approved: Bool
    let scopes: [String]
    let requestId: String

    init(
        personaId: String,
        personaLabel: String,
        serviceName: String,
        timestamp: Date = Date(),
        approved: Bool,
        scopes: [String],
        requestId: String
    ) {
        self.id = UUID()
        self.personaId = personaId
        self.personaLabel = personaLabel
        self.serviceName = serviceName
        self.timestamp = timestamp
        self.approved = approved
        self.scopes = scopes
        self.requestId = requestId
    }
}

final class ActivityStore: ObservableObject {
    @Published private(set) var events: [ActivityEvent] = []

    private let fileURL: URL

    init() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("IDAP")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.fileURL = dir.appendingPathComponent("activity.json")
        load()
    }

    func log(_ event: ActivityEvent) {
        events.insert(event, at: 0)
        save()
    }

    func events(for personaId: String) -> [ActivityEvent] {
        events.filter { $0.personaId == personaId }
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([ActivityEvent].self, from: data) else { return }
        events = decoded
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(events) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}
