// IDAPAuth — OIDC auth approval, JWT signing, WebSocket session, pre-authorization
// Depends on: IDAPCrypto, IDAPIdentity, GRDB

import CryptoKit
import Foundation
import GRDB
import IDAPCrypto
import IDAPIdentity

// MARK: - Auth Request

public struct AuthRequest: Codable, Equatable {
    public let requestId: String
    public let service: String
    public let serviceDisplayName: String
    public let personaHint: String?
    public let requesting: [String]
    public let nonce: String
    public let expiresAt: Date
    public let locationHint: String?

    public init(
        requestId: String, service: String, serviceDisplayName: String,
        personaHint: String? = nil, requesting: [String] = [],
        nonce: String, expiresAt: Date,
        locationHint: String? = nil
    ) {
        self.requestId = requestId
        self.service = service
        self.serviceDisplayName = serviceDisplayName
        self.personaHint = personaHint
        self.requesting = requesting
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.locationHint = locationHint
    }
}

public struct PIIRequest: Codable, Equatable {
    public let requestId: String
    public let service: String
    public let fields: [String]
    public let nonce: String
    public let expiresAt: Date
}

// MARK: - Signed Assertion

public struct SignedAssertion: Equatable {
    public let jwt: String
    public let requestId: String

    public init(jwt: String, requestId: String) {
        self.jwt = jwt
        self.requestId = requestId
    }
}

// MARK: - JWT Decode Helper (public, for tests)

public struct JWTPayload: Codable {
    public let sub: String
    public let aud: String
    public let nonce: String
    public let iat: Int
    public let exp: Int
    public let requestId: String
}

public func decodeJWT(_ jwt: String) -> (header: [String: Any], payload: JWTPayload, signatureData: Data, message: String)? {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else { return nil }

    func b64urlDecode(_ s: String) -> Data? {
        var s = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    guard let headerData = b64urlDecode(String(parts[0])),
          let payloadData = b64urlDecode(String(parts[1])),
          let sigData = b64urlDecode(String(parts[2])) else { return nil }

    guard let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
          let payload = try? JSONDecoder().decode(JWTPayload.self, from: payloadData) else { return nil }

    let message = "\(parts[0]).\(parts[1])"
    return (header, payload, sigData, message)
}

// MARK: - Pre-Authorization

public struct PreAuth: Equatable {
    public let id: String
    public let service: String
    public let personaId: String
    public let expiresAt: Date

    public init(id: String, service: String, personaId: String, expiresAt: Date) {
        self.id = id; self.service = service; self.personaId = personaId; self.expiresAt = expiresAt
    }
}

private struct PreAuthRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "pre_authorizations"
    var id: String
    var service: String
    var personaId: String
    var expiresAt: Double

    func toPreAuth() -> PreAuth {
        PreAuth(id: id, service: service, personaId: personaId,
                expiresAt: Date(timeIntervalSince1970: expiresAt))
    }

    static func from(_ p: PreAuth) -> PreAuthRow {
        PreAuthRow(id: p.id, service: p.service, personaId: p.personaId,
                   expiresAt: p.expiresAt.timeIntervalSince1970)
    }
}

// MARK: - WebSocket Abstraction

public protocol WebSocketConnectable: AnyObject {
    var isConnected: Bool { get }
    func connect(url: URL, headers: [String: String]) throws
    func send(_ message: String) throws
    func receive() -> String?
    func disconnect()
}

public final class MockWebSocketConnector: WebSocketConnectable {
    public private(set) var isConnected = false
    /// Fail the first `failCount` connect attempts.
    public var failCount: Int = 0
    private var connectAttempts = 0
    public private(set) var sentMessages: [String] = []
    private var incomingQueue: [String] = []
    public private(set) var connectCount = 0
    public private(set) var disconnectCount = 0

    public init() {}

    public func queueIncoming(_ message: String) { incomingQueue.append(message) }

    public func connect(url: URL, headers: [String: String]) throws {
        connectAttempts += 1
        connectCount += 1
        if connectAttempts <= failCount {
            throw URLError(.cannotConnectToHost)
        }
        isConnected = true
    }

    public func send(_ message: String) throws {
        guard isConnected else { throw URLError(.networkConnectionLost) }
        sentMessages.append(message)
    }

    public func receive() -> String? {
        incomingQueue.isEmpty ? nil : incomingQueue.removeFirst()
    }

    public func disconnect() {
        isConnected = false
        disconnectCount += 1
    }
}

// MARK: - Backoff Policy

public struct BackoffPolicy {
    public let intervals: [TimeInterval]

    public static let `default` = BackoffPolicy(intervals: [1, 2, 4, 8, 16, 30])

    public init(intervals: [TimeInterval]) { self.intervals = intervals }

    public func interval(for attempt: Int) -> TimeInterval {
        intervals[min(attempt, intervals.count - 1)]
    }
}

// MARK: - WebSocket Session

public final class IDAPWebSocketSession {
    private let auth: IDAPAuth
    public let connector: WebSocketConnectable
    public let backoffPolicy: BackoffPolicy
    public private(set) var reconnectCount = 0

    public var onAuthRequest: ((AuthRequest) -> Void)?
    public var onDenied: ((String) -> Void)?
    public var onGenericMessage: (([String: Any]) -> Void)?

    public init(auth: IDAPAuth, connector: WebSocketConnectable,
                backoffPolicy: BackoffPolicy = .default) {
        self.auth = auth
        self.connector = connector
        self.backoffPolicy = backoffPolicy
    }

    /// Connect to the proxy WebSocket, authenticated as the given persona.
    public func connect(url: URL, persona: Persona, seed: Data) throws {
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        let timestamp = String(Int(Date().timeIntervalSince1970))
        let msg = "GET:\(url.path):\(timestamp)"
        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: Data(msg.utf8))
        let headers: [String: String] = [
            "X-IDAP-Key": persona.publicKey.base64EncodedString(),
            "X-IDAP-Timestamp": timestamp,
            "X-IDAP-Signature": sig.base64EncodedString(),
        ]
        do {
            try connector.connect(url: url, headers: headers)
        } catch {
            reconnectCount += 1
            throw error
        }
    }

    public func backoffInterval(for attempt: Int) -> TimeInterval {
        backoffPolicy.interval(for: attempt)
    }

    /// Drain all pending incoming messages and fire callbacks.
    public func processIncoming() {
        while let message = connector.receive() {
            handleMessage(message)
        }
    }

    private func handleMessage(_ message: String) {
        guard let data = message.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = dict["type"] as? String else { return }
        switch type {
        case "auth_request":
            if let req = auth.parseAuthRequestDict(dict) { onAuthRequest?(req) }
        case "auth_denied", "auth_expired":
            onDenied?(dict["requestId"] as? String ?? "")
        default:
            onGenericMessage?(dict)
        }
    }

    /// Submit an approved assertion over WebSocket.
    public func submitAssertion(_ assertion: SignedAssertion) throws {
        let payload: [String: Any] = [
            "type": "auth_assertion",
            "requestId": assertion.requestId,
            "jwt": assertion.jwt,
        ]
        if let data = try? JSONSerialization.data(withJSONObject: payload),
           let str = String(data: data, encoding: .utf8) {
            try connector.send(str)
        }
    }

    public func disconnect() { connector.disconnect() }
}

// MARK: - IDAPAuth

public final class IDAPAuth {

    private let db: DatabaseQueue

    public init(db: DatabaseQueue) throws {
        self.db = db
        try applyMigrations()
    }

    public static func inMemory() throws -> IDAPAuth {
        try IDAPAuth(db: DatabaseQueue())
    }

    private func applyMigrations() throws {
        try db.write { db in
            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS pre_authorizations (
                    id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    personaId TEXT NOT NULL,
                    expiresAt REAL NOT NULL
                );
            """)
        }
    }

    // MARK: - Auth Request Parsing

    func parseAuthRequestDict(_ dict: [String: Any]) -> AuthRequest? {
        guard let requestId = dict["requestId"] as? String,
              let service = dict["service"] as? String,
              let displayName = dict["serviceDisplayName"] as? String,
              let nonce = dict["nonce"] as? String,
              let expiresAtRaw = dict["expiresAt"] as? Double else { return nil }
        let expiresAt = Date(timeIntervalSince1970: expiresAtRaw)
        guard expiresAt > Date() else { return nil }
        return AuthRequest(
            requestId: requestId, service: service, serviceDisplayName: displayName,
            personaHint: dict["personaHint"] as? String,
            requesting: dict["requesting"] as? [String] ?? [],
            nonce: nonce, expiresAt: expiresAt,
            locationHint: dict["locationHint"] as? String
        )
    }

    public func parsePIIRequest(_ userInfo: [AnyHashable: Any]) -> PIIRequest? {
        let dict = userInfo.reduce(into: [String: Any]()) { r, p in
            if let k = p.key as? String { r[k] = p.value }
        }
        guard let requestId = dict["requestId"] as? String,
              let service = dict["service"] as? String,
              let fields = dict["fields"] as? [String],
              let nonce = dict["nonce"] as? String,
              let expiresAtRaw = dict["expiresAt"] as? Double else { return nil }
        let expiresAt = Date(timeIntervalSince1970: expiresAtRaw)
        guard expiresAt > Date() else { return nil }
        return PIIRequest(requestId: requestId, service: service, fields: fields,
                         nonce: nonce, expiresAt: expiresAt)
    }

    // MARK: - Auth Approval

    /// Build and sign an EdDSA JWT approving the auth request.
    /// The private key is used transiently and not stored.
    public func approveAuthRequest(_ request: AuthRequest, persona: Persona, seed: Data) -> SignedAssertion {
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        let iat = Int(Date().timeIntervalSince1970)
        let exp = iat + 30

        let header = b64url(sortedJSON(["alg": "EdDSA", "typ": "JWT"]))
        let payload = b64url(sortedJSON([
            "sub": persona.publicKey.base64EncodedString(),
            "aud": request.service,
            "nonce": request.nonce,
            "iat": iat,
            "exp": exp,
            "requestId": request.requestId,
        ]))
        let signingInput = "\(header).\(payload)"
        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: Data(signingInput.utf8))
        let jwt = "\(signingInput).\(b64url(sig))"
        return SignedAssertion(jwt: jwt, requestId: request.requestId)
    }

    /// Deny a request. In production, would notify the proxy; here is a no-op at library level.
    public func denyAuthRequest(_ request: AuthRequest) {}

    // MARK: - Pre-Authorization

    public func createPreAuthorization(service: String, persona: Persona, seed: Data, ttl: TimeInterval) -> PreAuth {
        let p = PreAuth(id: UUID().uuidString, service: service, personaId: persona.id,
                        expiresAt: Date().addingTimeInterval(ttl))
        try? db.write { db in try PreAuthRow.from(p).save(db) }
        return p
    }

    public func checkPreAuthorization(service: String, persona: Persona) -> PreAuth? {
        let now = Date().timeIntervalSince1970
        let row = try? db.read { db in
            try PreAuthRow
                .filter(Column("service") == service
                    && Column("personaId") == persona.id
                    && Column("expiresAt") > now)
                .fetchOne(db)
        }
        return row?.toPreAuth()
    }

    public func listPreAuthorizations(persona: Persona) -> [PreAuth] {
        let now = Date().timeIntervalSince1970
        let rows = (try? db.read { db in
            try PreAuthRow
                .filter(Column("personaId") == persona.id && Column("expiresAt") > now)
                .fetchAll(db)
        }) ?? []
        return rows.map { $0.toPreAuth() }
    }

    public func pruneExpiredPreAuthorizations() {
        let now = Date().timeIntervalSince1970
        try? db.write { db in
            try db.execute(sql: "DELETE FROM pre_authorizations WHERE expiresAt <= ?", arguments: [now])
        }
    }

    // MARK: - Login Code

    public struct LoginCode: Codable, Equatable {
        public let code: String
        public let expiresIn: Int
        enum CodingKeys: String, CodingKey { case code; case expiresIn = "expires_in" }
    }

    public func requestLoginCode(persona: Persona, seed: Data, proxyURL: URL? = nil) async throws -> LoginCode {
        guard let proxy = proxyURL ?? persona.primaryProxy else {
            throw URLError(.badURL)
        }
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        let url = proxy.appendingPathComponent("auth/login-code")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"

        let timestamp = String(Int(Date().timeIntervalSince1970))
        let msg = "POST:/auth/login-code:\(timestamp)"
        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: Data(msg.utf8))

        request.setValue(persona.publicKey.base64EncodedString(), forHTTPHeaderField: "X-IDAP-Key")
        request.setValue(timestamp, forHTTPHeaderField: "X-IDAP-Timestamp")
        request.setValue(sig.base64EncodedString(), forHTTPHeaderField: "X-IDAP-Signature")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 201 else {
            throw URLError(.badServerResponse)
        }
        return try JSONDecoder().decode(LoginCode.self, from: data)
    }

    // MARK: - JWT / Base64url Utilities

    private func sortedJSON(_ dict: [String: Any]) -> Data {
        let pairs = dict.keys.sorted().map { key -> String in
            let v = dict[key]!
            if let s = v as? String { return "\"\(key)\":\"\(s)\"" }
            return "\"\(key)\":\(v)"
        }.joined(separator: ",")
        return Data("{\(pairs)}".utf8)
    }

    private func b64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
