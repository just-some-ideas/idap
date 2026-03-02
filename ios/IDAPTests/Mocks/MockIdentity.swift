import Foundation
import IDAPIdentity
import IDAPCrypto
@testable import IDAP

final class MockIdentity: IdentityStoring {
    var personas: [Persona] = []
    var createPersonaCalled: Bool = false
    var deletePersonaCalled: Bool = false
    var registeredProxies: [(URL, String)] = []
    var removedProxies: [(URL, String)] = []
    var updatedProfiles: [(PersonaProfile, String)] = []
    private var maxAllocatedIndex: Int = -1

    func createPersona(seed: Data, index: UInt32, id: String?, displayName: String?) -> Persona {
        createPersonaCalled = true
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: index)
        let profile = displayName.map { PersonaProfile(displayName: $0) }
        let persona = Persona(
            id: id ?? "real",
            derivationIndex: index,
            publicKey: kp.publicKey,
            publicProfile: profile
        )
        personas.append(persona)
        maxAllocatedIndex = max(maxAllocatedIndex, Int(index))
        return persona
    }

    func listPersonas() -> [Persona] { personas }

    func nextDerivationIndex() -> UInt32 {
        if maxAllocatedIndex < 0 { return 0 }
        return UInt32(maxAllocatedIndex + 1)
    }

    func deletePersona(_ persona: Persona) {
        deletePersonaCalled = true
        personas.removeAll { $0.id == persona.id }
    }

    func getPersonaKey(persona: Persona, seed: Data) -> KeyPair {
        IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
    }

    func signRecord(_ record: UnsignedRecord, persona: Persona, seed: Data) -> SignedRecord {
        let json = """
        {
            "type": ["VerifiableCredential"],
            "issuer": "\(record.issuer)",
            "issuedTo": "\(record.issuedTo)",
            "issuanceDate": "2024-01-01T00:00:00Z",
            "credentialSubject": {},
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": "",
                "signature": ""
            }
        }
        """
        return try! JSONDecoder().decode(SignedRecord.self, from: Data(json.utf8))
    }

    func registerProxy(_ url: URL, for persona: Persona) {
        registeredProxies.append((url, persona.id))
    }

    func removeProxy(_ url: URL, from persona: Persona) {
        removedProxies.append((url, persona.id))
    }

    func updateProfile(_ profile: PersonaProfile, for persona: Persona) {
        updatedProfiles.append((profile, persona.id))
    }
}
