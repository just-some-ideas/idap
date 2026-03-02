import Foundation
import IDAPIdentity
import IDAPCrypto

protocol IdentityStoring {
    func createPersona(seed: Data, index: UInt32, id: String?, displayName: String?) -> Persona
    func listPersonas() -> [Persona]
    func nextDerivationIndex() -> UInt32
    func deletePersona(_ persona: Persona)
    func getPersonaKey(persona: Persona, seed: Data) -> KeyPair
    func signRecord(_ record: UnsignedRecord, persona: Persona, seed: Data) -> SignedRecord
    func registerProxy(_ url: URL, for persona: Persona)
    func removeProxy(_ url: URL, from persona: Persona)
    func updateProfile(_ profile: PersonaProfile, for persona: Persona)
}
