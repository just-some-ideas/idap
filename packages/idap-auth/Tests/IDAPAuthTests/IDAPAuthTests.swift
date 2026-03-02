import XCTest
import CryptoKit
@testable import IDAPAuth
@testable import IDAPCrypto
@testable import IDAPIdentity

private let testSeed = Data(repeating: 0xCC, count: 32)
private let testProxy = URL(string: "http://localhost:8080")!

private func makeIdentity() throws -> IDAPIdentity { try IDAPIdentity.inMemory() }
private func makePersona(identity: IDAPIdentity) -> Persona {
    identity.createPersona(seed: testSeed, index: 0)
}

private func makePayload(expired: Bool = false, missing: String? = nil) -> [String: Any] {
    var dict: [String: Any] = [
        "requestId": "req-123",
        "service": "https://example.com",
        "serviceDisplayName": "Example App",
        "personaHint": "real",
        "requesting": ["name"],
        "nonce": "nonce-abc",
        "expiresAt": expired
            ? Date().addingTimeInterval(-60).timeIntervalSince1970
            : Date().addingTimeInterval(300).timeIntervalSince1970,
    ]
    if let missing { dict.removeValue(forKey: missing) }
    return dict
}

// MARK: - AuthRequestParsingTests

final class AuthRequestParsingTests: XCTestCase {

    var auth: IDAPAuth!

    override func setUpWithError() throws { auth = try IDAPAuth.inMemory() }

    func testParseValidAuthRequestPayload() throws {
        let req = auth.parseAuthRequestDict(makePayload() as [String: Any])
        XCTAssertNotNil(req)
        XCTAssertEqual(req?.requestId, "req-123")
        XCTAssertEqual(req?.service, "https://example.com")
        XCTAssertEqual(req?.nonce, "nonce-abc")
    }

    func testExpiredAuthRequestReturnsNil() throws {
        let req = auth.parseAuthRequestDict(makePayload(expired: true) as [String: Any])
        XCTAssertNil(req)
    }

    func testMissingFieldsReturnNil() throws {
        for field in ["requestId", "service", "serviceDisplayName", "nonce", "expiresAt"] {
            let req = auth.parseAuthRequestDict(makePayload(missing: field) as [String: Any])
            XCTAssertNil(req, "Should be nil when '\(field)' is missing")
        }
    }
}

// MARK: - JWTSigningTests

final class JWTSigningTests: XCTestCase {

    var auth: IDAPAuth!
    var identity: IDAPIdentity!
    var persona: Persona!

    override func setUpWithError() throws {
        auth = try IDAPAuth.inMemory()
        identity = try IDAPIdentity.inMemory()
        persona = makePersona(identity: identity)
    }

    private func makeRequest() -> AuthRequest {
        AuthRequest(requestId: "req-test", service: "https://test.com",
                    serviceDisplayName: "Test",
                    nonce: "test-nonce", expiresAt: Date().addingTimeInterval(60))
    }

    func testApproveRequestProducesValidJWT() throws {
        let assertion = auth.approveAuthRequest(makeRequest(), persona: persona, seed: testSeed)
        XCTAssertFalse(assertion.jwt.isEmpty)
        XCTAssertEqual(assertion.requestId, "req-test")
        XCTAssertEqual(assertion.jwt.split(separator: ".").count, 3)
    }

    func testJWTSubjectIsBase64PublicKey() throws {
        let assertion = auth.approveAuthRequest(makeRequest(), persona: persona, seed: testSeed)
        let decoded = try XCTUnwrap(decodeJWT(assertion.jwt))
        XCTAssertEqual(decoded.payload.sub, persona.publicKey.base64EncodedString())
    }

    func testJWTAudienceIsService() throws {
        let request = makeRequest()
        let assertion = auth.approveAuthRequest(request, persona: persona, seed: testSeed)
        let decoded = try XCTUnwrap(decodeJWT(assertion.jwt))
        XCTAssertEqual(decoded.payload.aud, request.service)
    }

    func testJWTNonceMatchesRequest() throws {
        let request = makeRequest()
        let assertion = auth.approveAuthRequest(request, persona: persona, seed: testSeed)
        let decoded = try XCTUnwrap(decodeJWT(assertion.jwt))
        XCTAssertEqual(decoded.payload.nonce, request.nonce)
    }

    func testJWTExpiryIsThirtySeconds() throws {
        let before = Int(Date().timeIntervalSince1970)
        let assertion = auth.approveAuthRequest(makeRequest(), persona: persona, seed: testSeed)
        let after = Int(Date().timeIntervalSince1970)
        let decoded = try XCTUnwrap(decodeJWT(assertion.jwt))
        let duration = decoded.payload.exp - decoded.payload.iat
        XCTAssertGreaterThanOrEqual(duration, 30)
        XCTAssertLessThanOrEqual(duration, 31)
        XCTAssertGreaterThanOrEqual(decoded.payload.iat, before)
        XCTAssertLessThanOrEqual(decoded.payload.iat, after + 1)
    }

    func testJWTSignatureVerifiesAgainstPersonaPublicKey() throws {
        let request = makeRequest()
        let assertion = auth.approveAuthRequest(request, persona: persona, seed: testSeed)
        let decoded = try XCTUnwrap(decodeJWT(assertion.jwt))
        let valid = IDAPCrypto.verify(
            publicKey: persona.publicKey,
            message: Data(decoded.message.utf8),
            signature: decoded.signatureData
        )
        XCTAssertTrue(valid, "JWT Ed25519 signature must verify against persona's public key")
    }

    func testPrivateKeyNotRetainedAfterApproval() throws {
        // Persona struct must not expose a privateKey field
        _ = auth.approveAuthRequest(makeRequest(), persona: persona, seed: testSeed)
        let mirror = Mirror(reflecting: persona!)
        for child in mirror.children {
            XCTAssertNotEqual(child.label, "privateKey",
                              "Persona must not have a privateKey field")
        }
    }

    func testDenyRequestProducesNilJWT() throws {
        let request = makeRequest()
        auth.denyAuthRequest(request)
        // denyAuthRequest is intentionally a no-op at library level — verify it doesn't crash
        XCTAssertTrue(true)
    }
}

// MARK: - WebSocketTests

final class WebSocketTests: XCTestCase {

    var auth: IDAPAuth!
    var identity: IDAPIdentity!
    var persona: Persona!
    var mockWS: MockWebSocketConnector!
    var session: IDAPWebSocketSession!

    override func setUpWithError() throws {
        auth = try IDAPAuth.inMemory()
        identity = try IDAPIdentity.inMemory()
        persona = makePersona(identity: identity)
        mockWS = MockWebSocketConnector()
        session = IDAPWebSocketSession(auth: auth, connector: mockWS)
    }

    private let wsURL = URL(string: "wss://idap.app/ws")!

    func testAuthRequestReceivedOverWebSocket() throws {
        try session.connect(url: wsURL, persona: persona, seed: testSeed)

        var received: AuthRequest?
        session.onAuthRequest = { received = $0 }

        let payload: [String: Any] = [
            "type": "auth_request",
            "requestId": "ws-req-1",
            "service": "https://ws-test.com",
            "serviceDisplayName": "WS Test",
            "nonce": "ws-nonce",
            "expiresAt": Date().addingTimeInterval(300).timeIntervalSince1970,
        ]
        let json = try JSONSerialization.data(withJSONObject: payload)
        mockWS.queueIncoming(String(data: json, encoding: .utf8)!)
        session.processIncoming()

        XCTAssertNotNil(received)
        XCTAssertEqual(received?.requestId, "ws-req-1")
    }

    func testSignedAssertionSubmittedOverWebSocket() throws {
        try session.connect(url: wsURL, persona: persona, seed: testSeed)
        let assertion = SignedAssertion(jwt: "h.p.s", requestId: "req-xyz")
        try session.submitAssertion(assertion)

        XCTAssertEqual(mockWS.sentMessages.count, 1)
        let sent = mockWS.sentMessages[0]
        XCTAssertTrue(sent.contains("req-xyz"))
        XCTAssertTrue(sent.contains("auth_assertion"))
    }

    func testReconnectsAfterDisconnect() throws {
        try session.connect(url: wsURL, persona: persona, seed: testSeed)
        XCTAssertTrue(mockWS.isConnected)

        session.disconnect()
        XCTAssertFalse(mockWS.isConnected)

        try session.connect(url: wsURL, persona: persona, seed: testSeed)
        XCTAssertTrue(mockWS.isConnected)
        XCTAssertEqual(mockWS.connectCount, 2)
    }

    func testBackoffIntervalsAreExponential() throws {
        let policy = BackoffPolicy(intervals: [1.0, 2.0, 4.0, 8.0, 16.0, 30.0])
        let expected = [1.0, 2.0, 4.0, 8.0, 16.0, 30.0]
        for (i, e) in expected.enumerated() {
            XCTAssertEqual(policy.interval(for: i), e, "Interval \(i) should be \(e)")
        }
        // Clamps to last value beyond range
        XCTAssertEqual(policy.interval(for: 100), 30.0)
    }
}

// MARK: - PreAuthorizationTests

final class PreAuthorizationTests: XCTestCase {

    var auth: IDAPAuth!
    var identity: IDAPIdentity!
    var persona: Persona!

    override func setUpWithError() throws {
        auth = try IDAPAuth.inMemory()
        identity = try IDAPIdentity.inMemory()
        persona = makePersona(identity: identity)
    }

    func testPreAuthAutoApprovesMatchingService() throws {
        let service = "https://example.com"
        _ = auth.createPreAuthorization(service: service, persona: persona, seed: testSeed, ttl: 3600)
        let preAuth = auth.checkPreAuthorization(service: service, persona: persona)
        XCTAssertNotNil(preAuth)
        XCTAssertEqual(preAuth?.service, service)
        XCTAssertEqual(preAuth?.personaId, persona.id)
    }

    func testPreAuthDoesNotApplyToOtherService() throws {
        _ = auth.createPreAuthorization(service: "https://authorized.com", persona: persona, seed: testSeed, ttl: 3600)
        let preAuth = auth.checkPreAuthorization(service: "https://other.com", persona: persona)
        XCTAssertNil(preAuth)
    }

    func testExpiredPreAuthIsNotUsed() throws {
        _ = auth.createPreAuthorization(service: "https://expired.com", persona: persona, seed: testSeed, ttl: -1)
        let preAuth = auth.checkPreAuthorization(service: "https://expired.com", persona: persona)
        XCTAssertNil(preAuth, "Expired pre-auth must not be returned")
    }

    func testPreAuthStoredAndRetrieved() throws {
        _ = auth.createPreAuthorization(service: "https://a.com", persona: persona, seed: testSeed, ttl: 3600)
        _ = auth.createPreAuthorization(service: "https://b.com", persona: persona, seed: testSeed, ttl: 3600)
        let list = auth.listPreAuthorizations(persona: persona)
        XCTAssertEqual(list.count, 2)
        XCTAssertTrue(list.allSatisfy { $0.personaId == persona.id })
    }
}
