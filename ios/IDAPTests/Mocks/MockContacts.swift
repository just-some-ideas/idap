import Foundation
import IDAPContacts
import IDAPIdentity
import IDAPCrypto
@testable import IDAP

final class MockContacts: ContactsProviding {
    var contacts: [Contact] = []
    var removedContact: Contact?
    var grants: [StoredGrant] = []
    var lastCapabilityRequest: CapabilityRequest?
    var lastCapabilityGrant: CapabilityGrant?

    func listContacts(persona: Persona) -> [Contact] {
        contacts.filter { $0.personaId == persona.id }
    }

    func storeContact(_ contact: Contact) {
        contacts.removeAll { $0.id == contact.id }
        contacts.append(contact)
    }

    func removeContact(_ contact: Contact) {
        removedContact = contact
        contacts.removeAll { $0.id == contact.id }
    }

    func generateKeyBundle(persona: Persona, seed: Data, oneTimePreKeyCount: Int) -> ContactKeyBundlePrivate {
        let identityKP = IDAPCrypto.generateEphemeralX25519FromSeed(seed)
        let preKP = IDAPCrypto.generateEphemeralX25519()
        let sig = IDAPCrypto.sign(privateKey: identityKP.privateKey, message: preKP.publicKey)
        let otPreKeys = (0..<oneTimePreKeyCount).map { _ in IDAPCrypto.generateEphemeralX25519() }
        let bundle = ContactKeyBundle(
            personaId: persona.id,
            identityPublicKey: identityKP.publicKey,
            signedPreKey: preKP.publicKey,
            signedPreKeySignature: sig,
            oneTimePreKeys: otPreKeys.map { $0.publicKey }
        )
        return ContactKeyBundlePrivate(
            bundle: bundle,
            identityPrivateKey: identityKP.privateKey,
            signedPreKeyPrivate: preKP.privateKey,
            oneTimePreKeyPrivates: otPreKeys.map { $0.privateKey }
        )
    }

    func buildCapabilityRequest(myPersona: Persona, seed: Data, myEndpoint: URL, myAccessCode: String, requestedAccess: RequestedAccess, identity: [String: String]?) -> CapabilityRequest {
        let req = CapabilityRequest(requestId: UUID().uuidString, requestedAccess: requestedAccess,
                                     replyPath: ReplyPath(endpoint: myEndpoint, pubkey: Data(repeating: 0, count: 32), accessCode: myAccessCode),
                                     identity: identity)
        lastCapabilityRequest = req
        return req
    }

    func buildCapabilityGrant(request: CapabilityRequest, grantedAccess: GrantedAccess, myPersona: Persona, seed: Data, myEndpoint: URL, myAccessCode: String?, bidirectional: Bool) -> CapabilityGrant {
        let grant = CapabilityGrant(grantId: UUID().uuidString, requestId: request.requestId, grantedAccess: grantedAccess)
        lastCapabilityGrant = grant
        return grant
    }

    func buildCapabilityDenial(requestId: String, reason: String?) -> CapabilityDenial {
        CapabilityDenial(requestId: requestId, reason: reason)
    }

    func storeGrant(_ grant: StoredGrant) {
        grants.removeAll { $0.grantId == grant.grantId }
        grants.append(grant)
    }

    func listGrants(persona: Persona) -> [StoredGrant] {
        grants.filter { $0.personaId == persona.id }
    }

    func revokeGrant(grantId: String) {
        grants.removeAll { $0.grantId == grantId }
    }

    func decryptMessageHeader(encryptedHeader: Data, myPrivateKey: Data, ephemeralPublicKey: Data) -> MessageHeader? {
        nil
    }

    func decryptMessagePayload(type: String, encryptedPayload: Data, myPrivateKey: Data, ephemeralPublicKey: Data) -> InboxMessage? {
        nil
    }
}
