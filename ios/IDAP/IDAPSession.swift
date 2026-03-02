import Foundation
import Combine
import IDAPIdentity
import IDAPAuth
import IDAPContacts
import IDAPCrypto
import IDAPRecovery

/// Response item from GET /inbox/{pubkey}
struct InboxHeaderItem: Codable, Identifiable {
    let id: String
    let header: String
    let deliveredAt: Int

    enum CodingKeys: String, CodingKey {
        case id
        case header
        case deliveredAt = "delivered_at"
    }
}

@MainActor
final class IDAPSession: ObservableObject {
    // MARK: - Published state

    @Published var isOnboarded: Bool
    @Published var isUnlocked: Bool = false
    @Published var personas: [Persona] = []
    @Published var activePersona: Persona?
    @Published var pendingAuthRequest: AuthRequest?
    @Published var pendingCapabilityRequests: [CapabilityRequest] = []
    @Published var contactsVersion: Int = 0
    @Published var deepLinkURL: URL?

    // MARK: - Services (package instances)

    let identity: IDAPIdentity
    let auth: IDAPAuth
    let contacts: IDAPContacts
    let recovery: IDAPRecovery

    // MARK: - App-layer services

    let keychain: KeychainService
    let activityStore: ActivityStore
    private(set) var wsSession: IDAPWebSocketSession?

    // MARK: - Ephemeral seed (zeroed on lock / background)

    private(set) var seed: Data?

    /// Maps CapabilityRequest.requestId → inbox message ID for deletion after approve/deny
    private var requestMessageIds: [String: String] = [:]

    // MARK: - Init

    init() {
        let db = DatabaseManager.shared
        self.identity = try! IDAPIdentity(db: db.identityQueue)
        self.auth = try! IDAPAuth(db: db.authQueue)
        self.contacts = try! IDAPContacts(db: db.contactsQueue)
        self.recovery = IDAPRecovery(store: db.recoveryMapStore)
        self.keychain = KeychainService()
        self.activityStore = ActivityStore()
        self.isOnboarded = UserDefaults.standard.bool(forKey: "idap.onboarded")
    }

    // MARK: - Lock / unlock

    func unlock(seed: Data) {
        self.seed = seed
        self.isUnlocked = true
        refreshPersonas()
        connectWebSocket()
    }

    func lock() {
        zeroSeed()
        isUnlocked = false
        wsSession?.disconnect()
        wsSession = nil
    }

    func markOnboarded() {
        isOnboarded = true
        UserDefaults.standard.set(true, forKey: "idap.onboarded")
    }

    // MARK: - Persona management

    func refreshPersonas() {
        personas = identity.listPersonas()
        let savedId = UserDefaults.standard.string(forKey: "idap.activePersonaId")
        activePersona = personas.first(where: { $0.id == savedId }) ?? personas.first
    }

    func setActivePersona(_ persona: Persona) {
        activePersona = persona
        UserDefaults.standard.set(persona.id, forKey: "idap.activePersonaId")
        pendingCapabilityRequests = []
        connectWebSocket()
    }

    // MARK: - Deep link handling

    func handleDeepLink(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            deepLinkURL = url
            return
        }

        if components.scheme == "idap" && components.host == "connect" {
            let params = Dictionary(
                uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
                    item.value.map { (item.name, $0) }
                }
            )
            if let endpointStr = params["endpoint"],
               let endpoint = URL(string: endpointStr),
               let code = params["code"] {
                Task {
                    await handleIncomingCode(code, endpoint: endpoint)
                }
                return
            }
        }

        deepLinkURL = url
    }

    // MARK: - Login Code

    func requestLoginCode(proxyURL: URL? = nil) async throws -> IDAPAuth.LoginCode {
        guard let persona = activePersona, let seed else {
            throw URLError(.userAuthenticationRequired)
        }
        return try await auth.requestLoginCode(persona: persona, seed: seed, proxyURL: proxyURL)
    }

    // MARK: - Access Codes

    func generateAccessCode(proxyURL: URL? = nil) async throws -> AccessCode {
        guard let persona = activePersona, let seed else {
            throw URLError(.userAuthenticationRequired)
        }
        let pubkeyB64url = stdToB64url(persona.publicKey.base64EncodedString())
        let path = "inbox/\(pubkeyB64url)/access-code"
        let request = signedRequest(method: "POST", path: path, persona: persona, seed: seed, proxyURL: proxyURL)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 201 else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(AccessCode.self, from: data)
    }

    func resolveAccessCode(_ code: String, endpoint: URL) async throws -> ResolvedCode {
        let url = endpoint.appendingPathComponent("inbox/resolve/\(code)")
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(ResolvedCode.self, from: data)
    }

    // MARK: - Inbox

    func fetchInboxHeaders() async throws -> [InboxHeaderItem] {
        guard let persona = activePersona, let seed else {
            throw URLError(.userAuthenticationRequired)
        }
        let pubkeyB64url = stdToB64url(persona.publicKey.base64EncodedString())
        let path = "inbox/\(pubkeyB64url)"
        let request = signedRequest(method: "GET", path: path, persona: persona, seed: seed)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode([InboxHeaderItem].self, from: data)
    }

    func fetchInboxPayload(messageId: String) async throws -> Data {
        guard let persona = activePersona, let seed else {
            throw URLError(.userAuthenticationRequired)
        }
        let pubkeyB64url = stdToB64url(persona.publicKey.base64EncodedString())
        let path = "inbox/\(pubkeyB64url)/\(messageId)/payload"
        let request = signedRequest(method: "GET", path: path, persona: persona, seed: seed)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
        struct PayloadResponse: Codable { let payload: String }
        let resp = try JSONDecoder().decode(PayloadResponse.self, from: data)
        guard let payloadData = Data(base64Encoded: resp.payload) else {
            throw URLError(.cannotDecodeContentData)
        }
        return payloadData
    }

    func fetchInboxMessages() async {
        guard let persona = activePersona, let seed else { return }

        do {
            let headers = try await fetchInboxHeaders()
            let ikSeed = IDAPCrypto.hkdf(secret: seed,
                                          salt: Data("idap-contact-identity".utf8),
                                          info: Data(persona.id.utf8),
                                          length: 32)
            let identityKP = IDAPCrypto.generateEphemeralX25519FromSeed(ikSeed)

            var requests: [CapabilityRequest] = []

            for item in headers {
                guard let headerData = Data(base64Encoded: item.header) else { continue }
                guard headerData.count > 32 else { continue }
                let ephPub = Data(headerData[0..<32])
                let encHeader = Data(headerData[32...])

                guard let header = contacts.decryptMessageHeader(
                    encryptedHeader: encHeader, myPrivateKey: identityKP.privateKey,
                    ephemeralPublicKey: ephPub) else { continue }

                switch header.type {
                case "capability_request":
                    do {
                        let payloadData = try await fetchInboxPayload(messageId: item.id)
                        if let msg = contacts.decryptMessagePayload(
                            type: header.type, encryptedPayload: payloadData,
                            myPrivateKey: identityKP.privateKey,
                            ephemeralPublicKey: header.ephemeralPublicKey) {
                            if case .capabilityRequest(let req) = msg {
                                requests.append(req)
                                requestMessageIds[req.requestId] = item.id
                            }
                        }
                    } catch {
                        // Skip messages we can't fetch/decrypt
                    }

                case "capability_grant":
                    do {
                        let payloadData = try await fetchInboxPayload(messageId: item.id)
                        if let msg = contacts.decryptMessagePayload(
                            type: header.type, encryptedPayload: payloadData,
                            myPrivateKey: identityKP.privateKey,
                            ephemeralPublicKey: header.ephemeralPublicKey) {
                            if case .capabilityGrant(let grant) = msg {
                                let peerPubkey = grant.replyPath?.pubkey ?? Data()
                                let peerEndpoint = grant.replyPath?.endpoint ?? persona.primaryProxy ?? URL(string: "http://localhost:8080")!
                                let peerAgreementKey = grant.replyPath?.agreementKey?.decode() ?? Data()

                                let storedGrant = StoredGrant(
                                    grantId: grant.grantId,
                                    personaId: persona.id,
                                    peerPubkey: peerPubkey,
                                    peerEndpoint: peerEndpoint,
                                    grantedMessageTypes: grant.grantedAccess.messageTypes,
                                    grantedCategories: grant.grantedAccess.categories,
                                    expiresAt: grant.grantedAccess.expiresAt,
                                    direction: "outbound"
                                )
                                contacts.storeGrant(storedGrant)

                                let contact = Contact(
                                    id: UUID().uuidString,
                                    personaId: persona.id,
                                    publicKey: peerPubkey,
                                    identityPublicKey: peerAgreementKey,
                                    sharedSecret: Data(repeating: 0, count: 32),
                                    displayName: nil
                                )
                                contacts.storeContact(contact)

                                contactsVersion += 1

                                activityStore.log(ActivityEvent(
                                    personaId: persona.id,
                                    personaLabel: persona.displayLabel,
                                    serviceName: String(peerPubkey.base64EncodedString().prefix(8)),
                                    approved: true,
                                    scopes: grant.grantedAccess.messageTypes,
                                    requestId: grant.requestId
                                ))

                                await deleteInboxMessage(messageId: item.id)
                            }
                        }
                    } catch {
                        // Skip messages we can't fetch/decrypt
                    }

                default:
                    activityStore.log(ActivityEvent(
                        personaId: persona.id,
                        personaLabel: persona.displayLabel,
                        serviceName: "inbox:\(header.type)",
                        approved: true,
                        scopes: [],
                        requestId: item.id
                    ))
                    await deleteInboxMessage(messageId: item.id)
                }
            }

            pendingCapabilityRequests = requests
        } catch {
            // Inbox fetch is best-effort
        }
    }

    // MARK: - Capability Negotiation

    func handleIncomingCode(_ code: String, endpoint: URL) async {
        guard let persona = activePersona, let seed else { return }

        do {
            let resolved = try await resolveAccessCode(code, endpoint: endpoint)

            let myAccessCode = try await generateAccessCode()

            let requestedAccess = RequestedAccess(
                messageTypes: ["contact_card"],
                categories: ["identity"]
            )
            var identity: [String: String] = [:]
            if let name = persona.publicProfile?.displayName, !name.isEmpty {
                identity["name"] = name
            }

            let capRequest = contacts.buildCapabilityRequest(
                myPersona: persona, seed: seed,
                myEndpoint: persona.primaryProxy ?? URL(string: "http://localhost:8080")!,
                myAccessCode: myAccessCode.code,
                requestedAccess: requestedAccess,
                identity: identity.isEmpty ? nil : identity
            )

            // Encrypt and send to recipient's inbox using their X25519 agreement key
            guard let recipientIdentityKey = resolved.keyBundle.agreementKey.decode() else { return }
            let requestData = try JSONEncoder().encode(capRequest)

            // Encrypt payload first so we can embed its ephemeral key in the header
            let (encPayload, payloadEphPub) = IDAPCrypto.encryptForRecipient(
                recipientX25519PublicKey: recipientIdentityKey, plaintext: requestData)
            let payloadSerialized = encPayload.nonce + encPayload.tag + encPayload.ciphertext

            let header = MessageHeader(type: "capability_request",
                                       ephemeralPublicKey: payloadEphPub)
            guard let encResult = contacts.encryptMessageHeader(header, recipientX25519PublicKey: recipientIdentityKey) else { return }

            let headerB64 = (encResult.ephemeralPublicKey + encResult.encrypted).base64EncodedString()
            let payloadB64 = payloadSerialized.base64EncodedString()

            let recipientPubkeyB64url = stdToB64url(resolved.pubkey)
            let inboxURL = endpoint.appendingPathComponent("inbox/\(recipientPubkeyB64url)")
            var req = URLRequest(url: inboxURL)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let body: [String: String] = [
                "header": headerB64,
                "payload": payloadB64,
                "access_code": code
            ]
            req.httpBody = try JSONEncoder().encode(body)
            let (_, response) = try await URLSession.shared.data(for: req)
            // Message sent (best-effort)
        } catch {
            // Failed to process incoming code
        }
    }

    /// Delete an inbox message after it has been processed (approve/deny/grant received).
    func deleteProcessedRequest(_ requestId: String) async {
        guard let messageId = requestMessageIds.removeValue(forKey: requestId) else { return }
        await deleteInboxMessage(messageId: messageId)
    }

    // MARK: - Private

    private func deleteInboxMessage(messageId: String) async {
        guard let persona = activePersona, let seed else { return }
        let pubkeyB64url = stdToB64url(persona.publicKey.base64EncodedString())
        let path = "inbox/\(pubkeyB64url)/\(messageId)"
        let request = signedRequest(method: "DELETE", path: path, persona: persona, seed: seed)
        _ = try? await URLSession.shared.data(for: request)
    }

    private func signedRequest(method: String, path: String, persona: Persona, seed: Data, proxyURL: URL? = nil) -> URLRequest {
        let proxy = proxyURL ?? persona.primaryProxy ?? URL(string: "http://localhost:8080")!
        let url = proxy.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = method

        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let sigPath = "/\(path)"
        let sigMsg = "\(method):\(sigPath):\(timestamp)"
        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: Data(sigMsg.utf8))

        request.setValue(persona.publicKey.base64EncodedString(), forHTTPHeaderField: "X-IDAP-Key")
        request.setValue(timestamp, forHTTPHeaderField: "X-IDAP-Timestamp")
        request.setValue(sig.base64EncodedString(), forHTTPHeaderField: "X-IDAP-Signature")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        return request
    }

    private func zeroSeed() {
        guard var s = seed else { return }
        s.withUnsafeMutableBytes { ptr in
            memset(ptr.baseAddress!, 0, ptr.count)
        }
        seed = nil
    }

    private func connectWebSocket() {
        guard let persona = activePersona, let seed, isUnlocked,
              let proxy = persona.primaryProxy else { return }
        wsSession?.disconnect()
        let connector = URLSessionWebSocketConnector()
        let ws = IDAPWebSocketSession(auth: auth, connector: connector)
        ws.onAuthRequest = { [weak self] request in
            Task { @MainActor [weak self] in
                self?.pendingAuthRequest = request
            }
        }
        ws.onGenericMessage = { [weak self] dict in
            guard let type = dict["type"] as? String, type == "inbox_message" else { return }
            Task { @MainActor [weak self] in
                await self?.fetchInboxMessages()
            }
        }
        connector.onMessageReceived = { [weak ws] in
            ws?.processIncoming()
        }
        wsSession = ws
        let wsURL = proxy.appendingPathComponent("ws")
        try? ws.connect(url: wsURL, persona: persona, seed: seed)
        Task { [weak self] in
            await self?.fetchInboxMessages()
        }
    }
}

// MARK: - Preview support
extension IDAPSession {
    /// A shared instance suitable for SwiftUI previews and placeholder initialization.
    /// Not for use in production code paths.
    static let _preview: IDAPSession = IDAPSession()
}
