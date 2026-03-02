import Foundation
import IDAPCrypto
import IDAPIdentity

@MainActor
final class PersonaCreationViewModel: ObservableObject {
    @Published var displayName: String = ""
    @Published var isCreating: Bool = false
    @Published var errorMessage: String?
    @Published var createdPersona: Persona?

    private let identity: IdentityStoring
    private let session: IDAPSession

    var isFormValid: Bool { true }

    init(identity: IdentityStoring, session: IDAPSession) {
        self.identity = identity
        self.session = session
    }

    func createPersona() async {
        guard let seed = session.seed else { return }
        let nextIndex = identity.nextDerivationIndex()

        isCreating = true
        errorMessage = nil

        let name = displayName.trimmingCharacters(in: .whitespaces)
        let persona = identity.createPersona(
            seed: seed,
            index: nextIndex,
            id: nextIndex == 0 ? "real" : nil,
            displayName: name.isEmpty ? nil : name
        )

        session.refreshPersonas()
        session.setActivePersona(persona)
        createdPersona = persona
        isCreating = false
    }
}

/// Convert standard base64 to base64url (no padding).
func stdToB64url(_ s: String) -> String {
    s.replacingOccurrences(of: "+", with: "-")
     .replacingOccurrences(of: "/", with: "_")
     .replacingOccurrences(of: "=", with: "")
}
