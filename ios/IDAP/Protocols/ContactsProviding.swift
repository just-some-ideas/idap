import Foundation
import IDAPContacts
import IDAPIdentity

protocol ContactsProviding {
    func listContacts(persona: Persona) -> [Contact]
    func storeContact(_ contact: Contact)
    func removeContact(_ contact: Contact)
    func generateKeyBundle(persona: Persona, seed: Data, oneTimePreKeyCount: Int) -> ContactKeyBundlePrivate
    func buildCapabilityRequest(myPersona: Persona, seed: Data, myEndpoint: URL, myAccessCode: String, requestedAccess: RequestedAccess, identity: [String: String]?) -> CapabilityRequest
    func buildCapabilityGrant(request: CapabilityRequest, grantedAccess: GrantedAccess, myPersona: Persona, seed: Data, myEndpoint: URL, myAccessCode: String?, bidirectional: Bool) -> CapabilityGrant
    func buildCapabilityDenial(requestId: String, reason: String?) -> CapabilityDenial
    func storeGrant(_ grant: StoredGrant)
    func listGrants(persona: Persona) -> [StoredGrant]
    func revokeGrant(grantId: String)
    func decryptMessageHeader(encryptedHeader: Data, myPrivateKey: Data, ephemeralPublicKey: Data) -> MessageHeader?
    func decryptMessagePayload(type: String, encryptedPayload: Data, myPrivateKey: Data, ephemeralPublicKey: Data) -> InboxMessage?
}
