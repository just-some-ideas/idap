import Foundation

@MainActor
final class ActivityViewModel: ObservableObject {
    @Published var events: [ActivityEvent] = []

    private let store: ActivityStore
    private let session: IDAPSession

    init(store: ActivityStore, session: IDAPSession) {
        self.store = store
        self.session = session
    }

    func loadEvents() {
        guard let persona = session.activePersona else {
            events = []
            return
        }
        events = store.events(for: persona.id)
    }
}
