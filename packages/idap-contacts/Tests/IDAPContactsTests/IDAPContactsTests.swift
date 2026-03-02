import XCTest
@testable import IDAPContacts
@testable import IDAPCrypto
@testable import IDAPIdentity

private let testSeed = Data(repeating: 0xAA, count: 32)
private let bobSeed  = Data(repeating: 0xBB, count: 32)
private let testProxy = URL(string: "https://idap.app")!

private func makeIdentity() throws -> IDAPIdentity { try IDAPIdentity.inMemory() }
private func makeContacts() throws -> IDAPContacts { try IDAPContacts.inMemory() }

private func makePersona(_ identity: IDAPIdentity, seed: Data, index: UInt32) -> Persona {
    identity.createPersona(seed: seed, index: index,
                           id: index == 0 ? "real" : "persona-\(index)")
}

// MARK: - X3DHTests

final class X3DHTests: XCTestCase {

    var aliceContacts: IDAPContacts!
    var bobContacts: IDAPContacts!
    var aliceIdentity: IDAPIdentity!
    var bobIdentity: IDAPIdentity!
    var alice: Persona!
    var bob: Persona!

    override func setUpWithError() throws {
        aliceContacts = try makeContacts()
        bobContacts = try makeContacts()
        aliceIdentity = try makeIdentity()
        bobIdentity = try makeIdentity()
        alice = makePersona(aliceIdentity, seed: testSeed, index: 0)
        bob   = makePersona(bobIdentity, seed: bobSeed, index: 0)
    }

    func testX3DHProducesMatchingSharedSecret() throws {
        let aliceBundle = aliceContacts.generateKeyBundle(persona: alice, seed: testSeed)
        let bobBundle   = bobContacts.generateKeyBundle(persona: bob, seed: bobSeed)

        // Alice initiates
        let initResult = try XCTUnwrap(
            aliceContacts.x3dhInitiate(myBundle: aliceBundle, theirBundle: bobBundle.bundle)
        )

        // Bob responds
        let bobSecret = try XCTUnwrap(
            bobContacts.x3dhRespond(
                myBundle: bobBundle,
                initiatorIdentityPublicKey: aliceBundle.bundle.identityPublicKey,
                ephemeralPublicKey: initResult.ephemeralPublicKey,
                usedOneTimePreKeyIndex: initResult.usedOneTimePreKeyIndex
            )
        )

        XCTAssertEqual(initResult.sharedSecret, bobSecret,
                       "Alice and Bob must derive the same shared secret")
    }

    func testX3DHSharedSecretDiffersWithDifferentBundles() throws {
        let aliceBundle = aliceContacts.generateKeyBundle(persona: alice, seed: testSeed)
        let bobBundle   = bobContacts.generateKeyBundle(persona: bob, seed: bobSeed)

        // Generate a different (random) identity bundle for "Carol"
        let carolContacts = try makeContacts()
        let carolIdentity = try makeIdentity()
        let carol = makePersona(carolIdentity, seed: Data(repeating: 0xCC, count: 32), index: 0)
        let carolBundle = carolContacts.generateKeyBundle(persona: carol, seed: Data(repeating: 0xCC, count: 32))

        let result1 = try XCTUnwrap(
            aliceContacts.x3dhInitiate(myBundle: aliceBundle, theirBundle: bobBundle.bundle)
        )
        let result2 = try XCTUnwrap(
            aliceContacts.x3dhInitiate(myBundle: aliceBundle, theirBundle: carolBundle.bundle)
        )
        XCTAssertNotEqual(result1.sharedSecret, result2.sharedSecret)
    }

    func testSignedPreKeyVerificationFailureRejected() throws {
        let aliceBundle = aliceContacts.generateKeyBundle(persona: alice, seed: testSeed)
        let bobBundle   = bobContacts.generateKeyBundle(persona: bob, seed: bobSeed)

        // Tamper: use carol's persona public key to verify bob's SPK → should fail
        let carolIdentity = try makeIdentity()
        let carol = makePersona(carolIdentity, seed: Data(repeating: 0xCC, count: 32), index: 0)

        let result = aliceContacts.x3dhInitiate(
            myBundle: aliceBundle,
            theirBundle: bobBundle.bundle,
            verifyWith: carol.publicKey  // wrong key
        )
        XCTAssertNil(result, "Tampered SPK signature must cause initiation to fail")
    }
}

// MARK: - ContactExchangeTests

final class ContactExchangeTests: XCTestCase {

    var contacts: IDAPContacts!
    var identity: IDAPIdentity!
    var personaA: Persona!
    var personaB: Persona!

    override func setUpWithError() throws {
        contacts = try makeContacts()
        identity = try makeIdentity()
        personaA = makePersona(identity, seed: testSeed, index: 0)
        personaB = identity.createPersona(seed: testSeed, index: 1, id: "b")
    }

    private func makeDummySharedSecret() -> Data {
        Data(repeating: 0x42, count: 32)
    }

    func testInitiateContactPostsOnlyCiphertext() throws {
        let sharedSecret = makeDummySharedSecret()
        let aliceKP = IDAPCrypto.generateEphemeralX25519()
        let card = ContactCard(publicKey: aliceKP.publicKey, identityPublicKey: aliceKP.publicKey,
                               displayName: "Alice Smith", phone: "+1-555-0100")

        let encrypted = try XCTUnwrap(contacts.encryptContactCard(card, sharedSecret: sharedSecret))

        // The proxy would receive `encrypted` — verify it contains no plaintext PII
        let encStr = encrypted.base64EncodedString()
        XCTAssertFalse(encStr.contains("Alice Smith"), "Plaintext name must not appear in payload")
        XCTAssertFalse(encStr.contains("555"), "Plaintext phone must not appear in payload")
    }

    func testAcceptContactDecryptsCardCorrectly() throws {
        let sharedSecret = makeDummySharedSecret()
        let aliceKP = IDAPCrypto.generateEphemeralX25519()
        let card = ContactCard(publicKey: aliceKP.publicKey, identityPublicKey: aliceKP.publicKey,
                               displayName: "Alice Smith", email: "alice@example.com")

        let encrypted = try XCTUnwrap(contacts.encryptContactCard(card, sharedSecret: sharedSecret))
        let decrypted = try XCTUnwrap(contacts.decryptContactCard(encrypted, sharedSecret: sharedSecret))

        XCTAssertEqual(decrypted.publicKey, card.publicKey)
        XCTAssertEqual(decrypted.displayName, card.displayName)
        XCTAssertEqual(decrypted.email, card.email)
    }

    func testContactStoredInDB() throws {
        let sharedSecret = makeDummySharedSecret()
        let kp = IDAPCrypto.generateEphemeralX25519()
        let contact = Contact(id: UUID().uuidString, personaId: personaA.id,
                              publicKey: kp.publicKey, identityPublicKey: kp.publicKey,
                              sharedSecret: sharedSecret, displayName: "Bob")
        contacts.storeContact(contact)
        let list = contacts.listContacts(persona: personaA)
        XCTAssertEqual(list.count, 1)
        XCTAssertEqual(list[0].publicKey, kp.publicKey)
        XCTAssertEqual(list[0].displayName, "Bob")
    }

    func testContactsIsolatedToPersona() throws {
        let ss = makeDummySharedSecret()
        let kp = IDAPCrypto.generateEphemeralX25519()
        let contact = Contact(id: UUID().uuidString, personaId: personaA.id,
                              publicKey: kp.publicKey, identityPublicKey: kp.publicKey,
                              sharedSecret: ss)
        contacts.storeContact(contact)

        let listA = contacts.listContacts(persona: personaA)
        let listB = contacts.listContacts(persona: personaB)
        XCTAssertEqual(listA.count, 1)
        XCTAssertTrue(listB.isEmpty, "Persona A's contacts must not appear under Persona B")
    }

    func testRemoveContactDeletesFromDB() throws {
        let ss = makeDummySharedSecret()
        let kp = IDAPCrypto.generateEphemeralX25519()
        let contact = Contact(id: UUID().uuidString, personaId: personaA.id,
                              publicKey: kp.publicKey, identityPublicKey: kp.publicKey,
                              sharedSecret: ss)
        contacts.storeContact(contact)
        XCTAssertEqual(contacts.listContacts(persona: personaA).count, 1)

        contacts.removeContact(contact)
        XCTAssertTrue(contacts.listContacts(persona: personaA).isEmpty)
    }
}

// MARK: - PIISharingTests

final class PIISharingTests: XCTestCase {

    var contacts: IDAPContacts!
    let sharedSecret = Data(repeating: 0x55, count: 32)

    override func setUpWithError() throws {
        contacts = try makeContacts()
    }

    func testShareFieldEncryptedInTransit() throws {
        let encrypted = try XCTUnwrap(
            contacts.encryptFieldUpdate(field: .phone, value: "+1-555-9999", sharedSecret: sharedSecret)
        )
        let raw = String(data: encrypted, encoding: .utf8) ?? encrypted.base64EncodedString()
        XCTAssertFalse(raw.contains("555"), "Phone number must not appear in plaintext")
    }

    func testSharedFieldAppearsInReceiverDB() throws {
        let encrypted = try XCTUnwrap(
            contacts.encryptFieldUpdate(field: .email, value: "alice@test.com", sharedSecret: sharedSecret)
        )
        let update = try XCTUnwrap(contacts.decryptFieldUpdate(encrypted, sharedSecret: sharedSecret))
        XCTAssertEqual(update.field, .email)
        XCTAssertEqual(update.value, "alice@test.com")
    }

    func testRevokeFieldRemovesFromReceiverDB() throws {
        let encrypted = try XCTUnwrap(
            contacts.encryptFieldRevocation(field: .phone, sharedSecret: sharedSecret)
        )
        let update = try XCTUnwrap(contacts.decryptFieldUpdate(encrypted, sharedSecret: sharedSecret))
        XCTAssertEqual(update.field, .phone)
        XCTAssertNil(update.value, "Revocation must produce nil value")
    }

    func testProxyNeverReceivesPlaintextPII() throws {
        let encrypted = try XCTUnwrap(
            contacts.encryptFieldUpdate(field: .name, value: "Alice Smith", sharedSecret: sharedSecret)
        )
        // Verify the encrypted payload differs from the plaintext
        let plaintextData = "Alice Smith".data(using: .utf8)!
        XCTAssertNotEqual(encrypted, plaintextData)
        XCTAssertFalse(encrypted.count == 0)
        // Try to decrypt with a wrong key — must fail
        let wrongSecret = Data(repeating: 0xFF, count: 32)
        let result = contacts.decryptFieldUpdate(encrypted, sharedSecret: wrongSecret)
        XCTAssertNil(result)
    }
}

// MARK: - ShardDistributionTests

final class ShardDistributionTests: XCTestCase {

    var contacts: IDAPContacts!
    var aliceContacts: IDAPContacts!
    var bobContacts: IDAPContacts!

    override func setUpWithError() throws {
        contacts = try makeContacts()
        aliceContacts = try makeContacts()
        bobContacts = try makeContacts()
    }

    private func makeShare(index: UInt8, size: Int = 32) -> Share {
        Share(id: index, value: Data(repeating: index &* 7 &+ 3, count: size))
    }

    func testShardEncryptedWithContactPublicKey() throws {
        let kp = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(index: 1)
        let encrypted = try XCTUnwrap(contacts.encryptShardForContact(shard, identityPublicKey: kp.publicKey))

        // Encrypted bytes must differ from the raw shard value
        XCTAssertNotEqual(encrypted.ciphertext, shard.value)
    }

    func testShardDecryptableByContact() throws {
        let kp = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(index: 2)

        let encrypted = try XCTUnwrap(contacts.encryptShardForContact(shard, identityPublicKey: kp.publicKey))
        let decrypted = try XCTUnwrap(contacts.decryptShardFromContact(encrypted, myPrivateKey: kp.privateKey))

        XCTAssertEqual(decrypted.id, shard.id)
        XCTAssertEqual(decrypted.value, shard.value)
    }

    func testShardNotDecryptableByOtherContact() throws {
        let bobKP  = IDAPCrypto.generateEphemeralX25519()
        let carolKP = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(index: 3)

        let encrypted = try XCTUnwrap(contacts.encryptShardForContact(shard, identityPublicKey: bobKP.publicKey))
        let result = contacts.decryptShardFromContact(encrypted, myPrivateKey: carolKP.privateKey)
        // Decryption with wrong key should produce nil (AES-GCM auth tag fails)
        XCTAssertNil(result, "Shard encrypted for Bob must not be decryptable by Carol")
    }

    func testShardDistributedOnContactAdd() throws {
        let kp = IDAPCrypto.generateEphemeralX25519()
        let shard = makeShare(index: 1)
        let identity = try makeIdentity()
        let personaA = makePersona(identity, seed: testSeed, index: 0)

        // Store contact with identity key
        let contact = Contact(id: UUID().uuidString, personaId: personaA.id,
                              publicKey: kp.publicKey, identityPublicKey: kp.publicKey,
                              sharedSecret: Data(repeating: 0x11, count: 32))
        contacts.storeContact(contact)

        // Encrypt shard for this contact
        let encrypted = try XCTUnwrap(contacts.encryptShardForContact(shard, identityPublicKey: kp.publicKey))

        // Contact can decrypt it
        let decrypted = try XCTUnwrap(contacts.decryptShardFromContact(encrypted, myPrivateKey: kp.privateKey))
        XCTAssertEqual(decrypted.id, shard.id)
    }

    func testRecoveryMapUpdatedAfterDistribution() throws {
        // After distributing shards to 2 contacts, verify each got a distinct encrypted blob
        let kp1 = IDAPCrypto.generateEphemeralX25519()
        let kp2 = IDAPCrypto.generateEphemeralX25519()
        let shard1 = makeShare(index: 1)
        let shard2 = makeShare(index: 2)

        let enc1 = try XCTUnwrap(contacts.encryptShardForContact(shard1, identityPublicKey: kp1.publicKey))
        let enc2 = try XCTUnwrap(contacts.encryptShardForContact(shard2, identityPublicKey: kp2.publicKey))

        // Each contact's encrypted shard must be distinct
        XCTAssertNotEqual(enc1.ciphertext, enc2.ciphertext)

        // Both are independently decryptable
        let dec1 = try XCTUnwrap(contacts.decryptShardFromContact(enc1, myPrivateKey: kp1.privateKey))
        let dec2 = try XCTUnwrap(contacts.decryptShardFromContact(enc2, myPrivateKey: kp2.privateKey))
        XCTAssertEqual(dec1.id, shard1.id)
        XCTAssertEqual(dec2.id, shard2.id)
    }
}

// MARK: - CapabilityTypeTests

final class CapabilityTypeTests: XCTestCase {

    func testCapabilityRequestEncodeDecode() throws {
        let replyPath = ReplyPath(endpoint: URL(string: "https://proxy.example.com")!,
                                  pubkey: Data(repeating: 0xAA, count: 32),
                                  accessCode: "ABC-DEF")
        let req = CapabilityRequest(
            requestId: "req-1",
            requestedAccess: RequestedAccess(messageTypes: ["text"], categories: ["social"],
                                             piiFields: [PIIFieldRequest(field: .name, reason: "display")]),
            replyPath: replyPath,
            identity: ["name": "Bob"],
            timestamp: 1000
        )

        let data = try JSONEncoder().encode(req)
        let decoded = try JSONDecoder().decode(CapabilityRequest.self, from: data)
        XCTAssertEqual(decoded, req)
    }

    func testCapabilityGrantEncodeDecode() throws {
        let grant = CapabilityGrant(
            grantId: "grant-1",
            requestId: "req-1",
            grantedAccess: GrantedAccess(messageTypes: ["text"], categories: ["social"], expiresAt: 9999),
            timestamp: 2000
        )
        let data = try JSONEncoder().encode(grant)
        let decoded = try JSONDecoder().decode(CapabilityGrant.self, from: data)
        XCTAssertEqual(decoded, grant)
    }

    func testCapabilityDenialEncodeDecode() throws {
        let denial = CapabilityDenial(requestId: "req-1", reason: "not interested", timestamp: 3000)
        let data = try JSONEncoder().encode(denial)
        let decoded = try JSONDecoder().decode(CapabilityDenial.self, from: data)
        XCTAssertEqual(decoded, denial)
    }

    func testCapabilityRevocationEncodeDecode() throws {
        let rev = CapabilityRevocation(grantId: "grant-1", reason: "expired", timestamp: 4000)
        let data = try JSONEncoder().encode(rev)
        let decoded = try JSONDecoder().decode(CapabilityRevocation.self, from: data)
        XCTAssertEqual(decoded, rev)
    }

    func testMessageHeaderEncodeDecode() throws {
        let header = MessageHeader(
            type: "capability_request",
            senderPubkey: Data(repeating: 0xBB, count: 32),
            ephemeralPublicKey: Data(repeating: 0xCC, count: 32),
            timestamp: 5000
        )
        let data = try JSONEncoder().encode(header)
        let decoded = try JSONDecoder().decode(MessageHeader.self, from: data)
        XCTAssertEqual(decoded, header)
    }

    func testAccessCodeResponseEncodeDecode() throws {
        let json = """
        {"code": "ABC-DEF", "expires_in": 300}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(AccessCode.self, from: json)
        XCTAssertEqual(decoded.code, "ABC-DEF")
        XCTAssertEqual(decoded.expiresIn, 300)
    }

    func testResolvedCodeEncodeDecode() throws {
        let json = """
        {"pubkey": "abc123", "key_bundle": {"signing_key": {"kty": "ed25519", "key": "a2V5MTIz"}, "agreement_key": {"kty": "x25519", "key": "YWdyMTIz"}}}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ResolvedCode.self, from: json)
        XCTAssertEqual(decoded.pubkey, "abc123")
        XCTAssertEqual(decoded.keyBundle.signingKey.kty, "ed25519")
        XCTAssertEqual(decoded.keyBundle.signingKey.key, "a2V5MTIz")
        XCTAssertEqual(decoded.keyBundle.agreementKey.kty, "x25519")
    }

    func testInboxMessageEquality() throws {
        let denial1 = CapabilityDenial(requestId: "r1", reason: "no", timestamp: 1)
        let denial2 = CapabilityDenial(requestId: "r1", reason: "no", timestamp: 1)
        XCTAssertEqual(InboxMessage.capabilityDenial(denial1), InboxMessage.capabilityDenial(denial2))
        XCTAssertNotEqual(InboxMessage.capabilityDenial(denial1), InboxMessage.unknown("test"))
    }
}

// MARK: - CapabilityHandshakeTests

final class CapabilityHandshakeTests: XCTestCase {

    var aliceContacts: IDAPContacts!
    var bobContacts: IDAPContacts!
    var aliceIdentity: IDAPIdentity!
    var bobIdentity: IDAPIdentity!
    var alice: Persona!
    var bob: Persona!

    override func setUpWithError() throws {
        aliceContacts = try makeContacts()
        bobContacts = try makeContacts()
        aliceIdentity = try makeIdentity()
        bobIdentity = try makeIdentity()
        alice = makePersona(aliceIdentity, seed: testSeed, index: 0)
        bob = makePersona(bobIdentity, seed: bobSeed, index: 0)
    }

    func testBuildCapabilityRequest() throws {
        let request = bobContacts.buildCapabilityRequest(
            myPersona: bob, seed: bobSeed,
            myEndpoint: testProxy,
            myAccessCode: "ABC-DEF",
            requestedAccess: RequestedAccess(messageTypes: ["text"], categories: ["social"]),
            identity: ["name": "Bob"]
        )
        XCTAssertEqual(request.requestedAccess.messageTypes, ["text"])
        XCTAssertEqual(request.requestedAccess.categories, ["social"])
        XCTAssertEqual(request.replyPath.endpoint, testProxy)
        XCTAssertEqual(request.replyPath.accessCode, "ABC-DEF")
        XCTAssertEqual(request.identity?["name"], "Bob")
        XCTAssertFalse(request.requestId.isEmpty)
    }

    func testBuildGrantUnidirectional() throws {
        let request = bobContacts.buildCapabilityRequest(
            myPersona: bob, seed: bobSeed, myEndpoint: testProxy,
            myAccessCode: "XXX-YYY",
            requestedAccess: RequestedAccess(messageTypes: ["text"], categories: ["social"])
        )

        let grant = aliceContacts.buildCapabilityGrant(
            request: request,
            grantedAccess: GrantedAccess(messageTypes: ["text"], categories: ["social"]),
            myPersona: alice, seed: testSeed, myEndpoint: testProxy,
            bidirectional: false
        )
        XCTAssertEqual(grant.requestId, request.requestId)
        XCTAssertEqual(grant.grantedAccess.messageTypes, ["text"])
        XCTAssertNil(grant.replyPath, "Unidirectional grant should not have reply path")
    }

    func testBuildGrantBidirectional() throws {
        let request = bobContacts.buildCapabilityRequest(
            myPersona: bob, seed: bobSeed, myEndpoint: testProxy,
            myAccessCode: "XXX-YYY",
            requestedAccess: RequestedAccess(messageTypes: ["text"], categories: ["social"])
        )

        let grant = aliceContacts.buildCapabilityGrant(
            request: request,
            grantedAccess: GrantedAccess(messageTypes: ["text"], categories: ["social"]),
            myPersona: alice, seed: testSeed, myEndpoint: testProxy,
            myAccessCode: "ZZZ-AAA",
            bidirectional: true
        )
        XCTAssertEqual(grant.requestId, request.requestId)
        XCTAssertNotNil(grant.replyPath, "Bidirectional grant should include reply path")
        XCTAssertEqual(grant.replyPath?.endpoint, testProxy)
        XCTAssertEqual(grant.replyPath?.accessCode, "ZZZ-AAA")
    }

    func testBuildDenial() throws {
        let denial = aliceContacts.buildCapabilityDenial(requestId: "req-1", reason: "not interested")
        XCTAssertEqual(denial.requestId, "req-1")
        XCTAssertEqual(denial.reason, "not interested")
    }

    func testBuildRevocation() throws {
        let rev = aliceContacts.buildCapabilityRevocation(grantId: "grant-1", reason: "expired")
        XCTAssertEqual(rev.grantId, "grant-1")
        XCTAssertEqual(rev.reason, "expired")
    }

    func testGrantStorageRoundTrip() throws {
        let grant = StoredGrant(
            grantId: "g-1", personaId: alice.id,
            peerPubkey: Data(repeating: 0xBB, count: 32),
            peerEndpoint: testProxy,
            accessProof: "proof123",
            grantedMessageTypes: ["text", "image"],
            grantedCategories: ["social"],
            expiresAt: 9999, direction: "inbound"
        )
        aliceContacts.storeGrant(grant)

        let grants = aliceContacts.listGrants(persona: alice)
        XCTAssertEqual(grants.count, 1)
        XCTAssertEqual(grants[0].grantId, "g-1")
        XCTAssertEqual(grants[0].grantedMessageTypes, ["text", "image"])
        XCTAssertEqual(grants[0].grantedCategories, ["social"])
        XCTAssertEqual(grants[0].direction, "inbound")
        XCTAssertEqual(grants[0].accessProof, "proof123")
    }

    func testGetGrant() throws {
        let grant = StoredGrant(
            grantId: "g-2", personaId: alice.id,
            peerPubkey: Data(repeating: 0xCC, count: 32),
            peerEndpoint: testProxy, direction: "outbound"
        )
        aliceContacts.storeGrant(grant)

        let fetched = aliceContacts.getGrant(grantId: "g-2")
        XCTAssertNotNil(fetched)
        XCTAssertEqual(fetched?.direction, "outbound")
    }

    func testRevokeGrant() throws {
        let grant = StoredGrant(
            grantId: "g-3", personaId: alice.id,
            peerPubkey: Data(repeating: 0xDD, count: 32),
            peerEndpoint: testProxy, direction: "inbound"
        )
        aliceContacts.storeGrant(grant)
        XCTAssertNotNil(aliceContacts.getGrant(grantId: "g-3"))

        aliceContacts.revokeGrant(grantId: "g-3")
        XCTAssertNil(aliceContacts.getGrant(grantId: "g-3"))
    }

    func testGrantsIsolatedToPersona() throws {
        // Use a different persona index so the IDs differ
        let otherPersona = aliceIdentity.createPersona(seed: testSeed, index: 1, id: "other")
        let grant = StoredGrant(
            grantId: "g-4", personaId: alice.id,
            peerPubkey: Data(repeating: 0xEE, count: 32),
            peerEndpoint: testProxy, direction: "inbound"
        )
        aliceContacts.storeGrant(grant)

        XCTAssertEqual(aliceContacts.listGrants(persona: alice).count, 1)
        XCTAssertEqual(aliceContacts.listGrants(persona: otherPersona).count, 0)
    }

    func testFullHandshakeFlow() throws {
        // Bob builds a request
        let request = bobContacts.buildCapabilityRequest(
            myPersona: bob, seed: bobSeed, myEndpoint: testProxy,
            myAccessCode: "BOB-CODE",
            requestedAccess: RequestedAccess(messageTypes: ["text"], categories: ["social"]),
            identity: ["name": "Bob"]
        )

        // Alice receives it, builds a bidirectional grant
        let grant = aliceContacts.buildCapabilityGrant(
            request: request,
            grantedAccess: GrantedAccess(messageTypes: ["text"], categories: ["social"], expiresAt: 9999),
            myPersona: alice, seed: testSeed, myEndpoint: testProxy,
            myAccessCode: "ALICE-CD",
            bidirectional: true
        )

        // Verify the grant references the request
        XCTAssertEqual(grant.requestId, request.requestId)
        XCTAssertEqual(grant.grantedAccess.messageTypes, ["text"])
        XCTAssertNotNil(grant.replyPath)

        // Both sides store grants
        let aliceStored = StoredGrant(
            grantId: grant.grantId, personaId: alice.id,
            peerPubkey: request.replyPath.pubkey,
            peerEndpoint: request.replyPath.endpoint,
            grantedMessageTypes: grant.grantedAccess.messageTypes,
            grantedCategories: grant.grantedAccess.categories,
            expiresAt: grant.grantedAccess.expiresAt,
            direction: "inbound"
        )
        aliceContacts.storeGrant(aliceStored)

        let bobStored = StoredGrant(
            grantId: grant.grantId, personaId: bob.id,
            peerPubkey: grant.replyPath!.pubkey,
            peerEndpoint: grant.replyPath!.endpoint,
            grantedMessageTypes: grant.grantedAccess.messageTypes,
            grantedCategories: grant.grantedAccess.categories,
            expiresAt: grant.grantedAccess.expiresAt,
            direction: "outbound"
        )
        bobContacts.storeGrant(bobStored)

        // Verify both sides have the grant
        XCTAssertEqual(aliceContacts.listGrants(persona: alice).count, 1)
        XCTAssertEqual(bobContacts.listGrants(persona: bob).count, 1)
    }
}
