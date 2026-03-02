import Foundation
import IDAPIdentity
import IDAPCrypto

@MainActor
final class PersonaDetailViewModel: ObservableObject {
    @Published var displayName: String
    @Published var bio: String
    @Published var proxies: [URL]
    @Published var errorMessage: String?
    @Published var isDeleted: Bool = false

    private(set) var persona: Persona
    let session: IDAPSession

    var profileDirty: Bool {
        displayName != (persona.publicProfile?.displayName ?? "") ||
        bio != (persona.publicProfile?.bio ?? "")
    }

    init(persona: Persona, session: IDAPSession) {
        self.persona = persona
        self.session = session
        self.displayName = persona.publicProfile?.displayName ?? ""
        self.bio = persona.publicProfile?.bio ?? ""
        self.proxies = persona.proxies
    }

    func saveProfile() {
        let profile = PersonaProfile(
            displayName: displayName.isEmpty ? nil : displayName,
            avatarHash: persona.publicProfile?.avatarHash,
            bio: bio.isEmpty ? nil : bio
        )
        session.identity.updateProfile(profile, for: persona)
        session.refreshPersonas()
        // Update local copy
        if let updated = session.personas.first(where: { $0.id == persona.id }) {
            persona = updated
        }
    }

    func removeProxy(_ url: URL) {
        session.identity.removeProxy(url, from: persona)
        refreshProxies()
    }

    func refreshProxies() {
        session.refreshPersonas()
        if let updated = session.personas.first(where: { $0.id == persona.id }) {
            persona = updated
            proxies = updated.proxies
        }
    }

    func deletePersona() {
        session.identity.deletePersona(persona)
        session.refreshPersonas()
        isDeleted = true
    }
}
