import Foundation
import IDAPContacts
import IDAPCrypto
import IDAPIdentity

@MainActor
final class CapabilityRequestViewModel: ObservableObject {
    enum State: Equatable {
        case pending
        case approving
        case approved
        case denied
    }

    @Published var state: State = .pending
    @Published var errorMessage: String?

    let request: CapabilityRequest
    private let session: IDAPSession

    init(request: CapabilityRequest, session: IDAPSession) {
        self.request = request
        self.session = session
    }

    func approve() async {
        guard let persona = session.activePersona, let seed = session.seed else { return }
        state = .approving
        errorMessage = nil

        let grantedAccess = GrantedAccess(
            messageTypes: request.requestedAccess.messageTypes,
            categories: request.requestedAccess.categories
        )

        let grant = session.contacts.buildCapabilityGrant(
            request: request,
            grantedAccess: grantedAccess,
            myPersona: persona,
            seed: seed,
            myEndpoint: persona.primaryProxy ?? URL(string: "http://localhost:8080")!,
            bidirectional: true
        )

        // Store the grant locally
        let storedGrant = StoredGrant(
            grantId: grant.grantId,
            personaId: persona.id,
            peerPubkey: request.replyPath.pubkey,
            peerEndpoint: request.replyPath.endpoint,
            grantedMessageTypes: grantedAccess.messageTypes,
            grantedCategories: grantedAccess.categories,
            expiresAt: grantedAccess.expiresAt,
            direction: "inbound"
        )
        session.contacts.storeGrant(storedGrant)

        // Create a Contact from the requester's info
        let displayName = request.identity?["name"] ?? request.identity?["displayName"]
        // Use the X25519 agreement key from the reply path (not the Ed25519 signing pubkey)
        let identityPublicKey = request.replyPath.agreementKey?.decode() ?? Data()
        let contact = Contact(
            id: UUID().uuidString,
            personaId: persona.id,
            publicKey: request.replyPath.pubkey,
            identityPublicKey: identityPublicKey,
            sharedSecret: Data(repeating: 0, count: 32),
            displayName: displayName
        )
        session.contacts.storeContact(contact)

        // Send the grant back to the requester's inbox
        await sendGrantToRequester(grant: grant, persona: persona, seed: seed)

        session.contactsVersion += 1
        session.activityStore.log(ActivityEvent(
            personaId: persona.id,
            personaLabel: persona.displayLabel,
            serviceName: displayName ?? String(request.replyPath.pubkey.base64EncodedString().prefix(8)),
            approved: true,
            scopes: grantedAccess.messageTypes,
            requestId: request.requestId
        ))

        await session.deleteProcessedRequest(request.requestId)

        state = .approved
        session.pendingCapabilityRequests.removeAll { $0.requestId == request.requestId }
    }

    func deny() async {
        guard let persona = session.activePersona else { return }
        _ = session.contacts.buildCapabilityDenial(
            requestId: request.requestId,
            reason: "User denied"
        )
        let displayName = request.identity?["name"] ?? request.identity?["displayName"]
        session.activityStore.log(ActivityEvent(
            personaId: persona.id,
            personaLabel: persona.displayLabel,
            serviceName: displayName ?? String(request.replyPath.pubkey.base64EncodedString().prefix(8)),
            approved: false,
            scopes: request.requestedAccess.messageTypes,
            requestId: request.requestId
        ))
        await session.deleteProcessedRequest(request.requestId)
        state = .denied
        session.pendingCapabilityRequests.removeAll { $0.requestId == request.requestId }
    }

    // MARK: - Private

    private func sendGrantToRequester(grant: CapabilityGrant, persona: Persona, seed: Data) async {
        let replyPath = request.replyPath
        guard let accessCode = replyPath.accessCode else { return }

        do {
            let grantData = try JSONEncoder().encode(grant)

            // Derive the recipient's X25519 identity key from their key bundle
            // For now, use their replyPath pubkey to look up their key bundle
            let recipientPubkeyB64 = replyPath.pubkey.base64EncodedString()
            let recipientPubkeyB64url = stdToB64url(recipientPubkeyB64)

            // Resolve the recipient's X25519 identity key from their key bundle
            let resolveURL = replyPath.endpoint.appendingPathComponent("inbox/resolve/\(accessCode)")
            let (resolveData, resolveResp) = try await URLSession.shared.data(from: resolveURL)
            guard let httpResp = resolveResp as? HTTPURLResponse, httpResp.statusCode == 200 else {
                // Access code may already be consumed; send grant using Ed25519 key as fallback
                return
            }
            let resolved = try JSONDecoder().decode(ResolvedCode.self, from: resolveData)
            guard let recipientIdentityKey = resolved.keyBundle.agreementKey.decode() else { return }

            // Encrypt payload first to get ephemeral key
            let (encPayload, payloadEphPub) = IDAPCrypto.encryptForRecipient(
                recipientX25519PublicKey: recipientIdentityKey, plaintext: grantData)
            let payloadSerialized = encPayload.nonce + encPayload.tag + encPayload.ciphertext

            // Create header with payload's ephemeral key
            let header = MessageHeader(type: "capability_grant", ephemeralPublicKey: payloadEphPub)
            guard let encResult = session.contacts.encryptMessageHeader(
                header, recipientX25519PublicKey: recipientIdentityKey) else { return }

            let headerB64 = (encResult.ephemeralPublicKey + encResult.encrypted).base64EncodedString()
            let payloadB64 = payloadSerialized.base64EncodedString()

            let inboxURL = replyPath.endpoint.appendingPathComponent("inbox/\(recipientPubkeyB64url)")
            var req = URLRequest(url: inboxURL)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: String] = [
                "header": headerB64,
                "payload": payloadB64,
                "access_code": accessCode
            ]
            req.httpBody = try JSONEncoder().encode(body)
            let (_, _) = try await URLSession.shared.data(for: req)
        } catch {
            // Grant send is best-effort; contact was still created locally
        }
    }
}
