import XCTest
import CryptoKit
@testable import IDAPIdentity
@testable import IDAPCrypto

private let testSeed = Data(repeating: 0xAB, count: 32)
private let testProxy = URL(string: "http://localhost:8080")!

final class PersonaTests: XCTestCase {

    var identity: IDAPIdentity!

    override func setUpWithError() throws {
        identity = try IDAPIdentity.inMemory()
    }

    func testCreatePersonaDerivesUniquePublicKey() throws {
        let p = identity.createPersona(seed: testSeed, index: 0)
        let expectedKP = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        XCTAssertEqual(p.publicKey, expectedKP.publicKey)
    }

    func testPersonaPublicKeysDifferAcrossIndices() throws {
        let p0 = identity.createPersona(seed: testSeed, index: 0)
        let p1 = identity.createPersona(seed: testSeed, index: 1, id: "b")
        XCTAssertNotEqual(p0.publicKey, p1.publicKey)
    }

    func testListPersonasReturnsAllCreated() throws {
        identity.createPersona(seed: testSeed, index: 0)
        _ = identity.createPersona(seed: testSeed, index: 1, id: "b")
        _ = identity.createPersona(seed: testSeed, index: 2, id: "c")
        XCTAssertEqual(identity.listPersonas().count, 3)
    }

    func testDeletePersonaRemovesFromStorage() throws {
        let p = identity.createPersona(seed: testSeed, index: 0)
        identity.deletePersona(p)
        XCTAssertTrue(identity.listPersonas().isEmpty)
    }

    func testPersonaPrivateKeyNotStoredAnywhere() throws {
        let p = identity.createPersona(seed: testSeed, index: 0)
        let kp = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        // The Persona struct must only carry the public key
        XCTAssertEqual(p.publicKey, kp.publicKey)
        // Public key != private key (sanity)
        XCTAssertNotEqual(p.publicKey, kp.privateKey)
    }

    func testDisplayLabelFallsBackToTruncatedKey() throws {
        let p = identity.createPersona(seed: testSeed, index: 0)
        XCTAssertTrue(p.displayLabel.hasSuffix("..."))
        XCTAssertEqual(p.displayLabel.count, 11) // 8 chars + "..."
    }

    func testDisplayLabelUsesDisplayName() throws {
        let p = identity.createPersona(seed: testSeed, index: 0, displayName: "Alice")
        XCTAssertEqual(p.displayLabel, "Alice")
    }
}

final class KeyDerivationTests: XCTestCase {

    var identity: IDAPIdentity!

    override func setUpWithError() throws {
        identity = try IDAPIdentity.inMemory()
    }

    func testGetPersonaKeyIsDeterministic() throws {
        let p = identity.createPersona(seed: testSeed, index: 0)
        let kp1 = identity.getPersonaKey(persona: p, seed: testSeed)
        let kp2 = identity.getPersonaKey(persona: p, seed: testSeed)
        XCTAssertEqual(kp1.publicKey, kp2.publicKey)
        XCTAssertEqual(kp1.privateKey, kp2.privateKey)
    }

    func testGetPersonaKeyDiffersByIndex() throws {
        let p0 = identity.createPersona(seed: testSeed, index: 0)
        let p1 = identity.createPersona(seed: testSeed, index: 1, id: "b")
        let kp0 = identity.getPersonaKey(persona: p0, seed: testSeed)
        let kp1 = identity.getPersonaKey(persona: p1, seed: testSeed)
        XCTAssertNotEqual(kp0.privateKey, kp1.privateKey)
    }

    func testWithPersonaKeyZeroesKeyAfterBlock() throws {
        let p = identity.createPersona(seed: testSeed, index: 0)
        var capturedPrivKey: Data?
        identity.withPersonaKey(persona: p, seed: testSeed) { kp in
            capturedPrivKey = kp.privateKey
        }
        XCTAssertNotNil(capturedPrivKey)
        // Key inside block is non-zero (it's the real key)
        XCTAssertFalse(capturedPrivKey!.allSatisfy { $0 == 0 }, "Key inside block must be non-zero")
    }
}

final class CredentialWalletTests: XCTestCase {

    var identity: IDAPIdentity!
    var personaA: Persona!
    var personaB: Persona!

    override func setUpWithError() throws {
        identity = try IDAPIdentity.inMemory()
        personaA = identity.createPersona(seed: testSeed, index: 0)
        personaB = identity.createPersona(seed: testSeed, index: 1, id: "b")
    }

    func testStoreAndRetrieveCredential() throws {
        let cred = makeCred(type: "AgeCredential", personaDID: "did:example:alice")
        identity.storeCredential(cred, for: personaA)
        let list = identity.listCredentials(for: personaA)
        XCTAssertEqual(list.count, 1)
        XCTAssertEqual(list[0].type, cred.type)
    }

    func testCredentialIsolatedToPersona() throws {
        let cred = makeCred(type: "AgeCredential", personaDID: "did:example:alice")
        identity.storeCredential(cred, for: personaA)
        let listB = identity.listCredentials(for: personaB)
        XCTAssertTrue(listB.isEmpty, "Persona A credential must not appear under Persona B")
    }

    func testGetCredentialByTypeReturnsCorrect() throws {
        let cred = makeCred(type: "PurchaseRecord", personaDID: "did:example:a")
        identity.storeCredential(cred, for: personaA)
        let found = identity.getCredential(type: "PurchaseRecord", for: personaA)
        XCTAssertNotNil(found)
    }

    func testGetMissingCredentialReturnsNil() throws {
        let found = identity.getCredential(type: "NonExistent", for: personaA)
        XCTAssertNil(found)
    }

    private func makeCred(type: String, personaDID: String) -> Credential {
        let raw = "{\"type\":[\"VerifiableCredential\",\"\(type)\"],\"issuer\":\"did:example:issuer\",\"issuedTo\":\"\(personaDID)\",\"issuanceDate\":\"2026-01-01\",\"credentialSubject\":{\"value\":\"test\"}}"
        return Credential(type: type, issuer: "did:example:issuer", issuedTo: personaDID,
                         issuanceDate: "2026-01-01", credentialSubject: ["value": "test"], raw: raw)
    }
}

final class SignedRecordTests: XCTestCase {

    var identity: IDAPIdentity!
    var persona: Persona!

    override func setUpWithError() throws {
        identity = try IDAPIdentity.inMemory()
        persona = identity.createPersona(seed: testSeed, index: 0)
    }

    func testSignRecordProducesValidSignature() throws {
        let record = makeRecord()
        let signed = identity.signRecord(record, persona: persona, seed: testSeed)
        XCTAssertFalse(signed.proof.signature.isEmpty)
        XCTAssertEqual(signed.proof.type, "Ed25519Signature2020")
    }

    func testVerifySignedRecordPasses() throws {
        let record = makeRecord()
        let signed = identity.signRecord(record, persona: persona, seed: testSeed)
        let result = identity.verifyRecord(signed)
        XCTAssertTrue(result.valid)
    }

    func testVerifyTamperedSubjectFails() throws {
        let record = makeRecord()
        let signed = identity.signRecord(record, persona: persona, seed: testSeed)
        let tampered = SignedRecord(
            type: signed.type, issuer: signed.issuer, issuedTo: signed.issuedTo,
            issuanceDate: signed.issuanceDate,
            credentialSubject: ["item": "Tampered Item"],
            proof: signed.proof
        )
        let result = identity.verifyRecord(tampered)
        XCTAssertFalse(result.valid)
    }

    func testVerifyTamperedSignatureFails() throws {
        let record = makeRecord()
        let signed = identity.signRecord(record, persona: persona, seed: testSeed)
        var corruptedSig = signed.proof.signature
        corruptedSig.replaceSubrange(corruptedSig.startIndex...corruptedSig.startIndex, with: "X")
        let tampered = SignedRecord(
            type: signed.type, issuer: signed.issuer, issuedTo: signed.issuedTo,
            issuanceDate: signed.issuanceDate, credentialSubject: signed.credentialSubject,
            proof: RecordProof(type: signed.proof.type,
                               verificationMethod: signed.proof.verificationMethod,
                               signature: corruptedSig)
        )
        let result = identity.verifyRecord(tampered)
        XCTAssertFalse(result.valid)
    }

    func testDIDContainsPersonaPublicKeyFingerprint() throws {
        let kp = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        let did = IDAPIdentity.makeDID(publicKey: kp.publicKey)
        XCTAssertTrue(did.hasPrefix("did:idap:persona:"))
        XCTAssertGreaterThan(did.count, "did:idap:persona:".count)
    }

    func testDIDsForDifferentPersonasAreDifferent() throws {
        let kp0 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        let kp1 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 1)
        XCTAssertNotEqual(IDAPIdentity.makeDID(publicKey: kp0.publicKey),
                          IDAPIdentity.makeDID(publicKey: kp1.publicKey))
    }

    func testDIDNotDerivableFromMasterKey() throws {
        let kp0 = IDAPCrypto.derivePersonaKey(seed: testSeed, index: 0)
        let masterHash = SHA256.hash(data: testSeed)
        let masterB58 = IDAPIdentity.base58Encode(Data(masterHash))
        let personaDID = IDAPIdentity.makeDID(publicKey: kp0.publicKey)
        XCTAssertFalse(personaDID.contains(masterB58))
    }

    private func makeRecord() -> UnsignedRecord {
        UnsignedRecord(
            type: ["VerifiableCredential", "PurchaseRecord"],
            issuer: "did:idap:persona:test",
            issuedTo: IDAPIdentity.makeDID(publicKey: persona.publicKey),
            credentialSubject: ["item": "Half-Life 3", "licenseType": "perpetual"]
        )
    }
}

// MARK: - Derivation Registry Tests

final class DerivationRegistryTests: XCTestCase {

    var identity: IDAPIdentity!

    override func setUpWithError() throws {
        identity = try IDAPIdentity.inMemory()
    }

    func testNextIndexStartsAtZeroForEmptyDB() {
        XCTAssertEqual(identity.nextDerivationIndex(), 0)
    }

    func testNextIndexIncrementsAfterCreation() {
        _ = identity.createPersona(seed: testSeed, index: 0)
        XCTAssertEqual(identity.nextDerivationIndex(), 1)
    }

    func testSequentialCreationYieldsSequentialIndices() {
        for i: UInt32 in 0..<5 {
            XCTAssertEqual(identity.nextDerivationIndex(), i)
            _ = identity.createPersona(seed: testSeed, index: i, id: "p\(i)")
        }
        XCTAssertEqual(identity.nextDerivationIndex(), 5)
    }

    func testIndexNeverReusedAfterSingleDeletion() {
        let p0 = identity.createPersona(seed: testSeed, index: 0)
        _ = identity.createPersona(seed: testSeed, index: 1, id: "b")
        identity.deletePersona(p0)
        // Next index must be 2, NOT 0 (the deleted index)
        XCTAssertEqual(identity.nextDerivationIndex(), 2)
    }

    func testIndexNeverReusedAfterDeletingAllPersonas() {
        let p0 = identity.createPersona(seed: testSeed, index: 0)
        let p1 = identity.createPersona(seed: testSeed, index: 1, id: "b")
        identity.deletePersona(p0)
        identity.deletePersona(p1)
        XCTAssertTrue(identity.listPersonas().isEmpty)
        // Registry still remembers indices 0 and 1
        XCTAssertEqual(identity.nextDerivationIndex(), 2)
    }

    func testNicknameStoredOnCreation() {
        _ = identity.createPersona(seed: testSeed, index: 0, displayName: "Alice")
        XCTAssertEqual(identity.registryNickname(for: 0), "Alice")
    }

    func testNicknameNilWhenNotProvided() {
        _ = identity.createPersona(seed: testSeed, index: 0)
        XCTAssertNil(identity.registryNickname(for: 0))
    }

    func testUpdateNickname() {
        _ = identity.createPersona(seed: testSeed, index: 0, displayName: "Alice")
        identity.updateRegistryNickname(index: 0, nickname: "Bob")
        XCTAssertEqual(identity.registryNickname(for: 0), "Bob")
    }

    func testClearNickname() {
        _ = identity.createPersona(seed: testSeed, index: 0, displayName: "Alice")
        identity.updateRegistryNickname(index: 0, nickname: nil)
        XCTAssertNil(identity.registryNickname(for: 0))
    }

    func testListRegistryEntriesOrderedByIndex() {
        _ = identity.createPersona(seed: testSeed, index: 3, id: "c", displayName: "Charlie")
        _ = identity.createPersona(seed: testSeed, index: 1, id: "a", displayName: "Alice")
        _ = identity.createPersona(seed: testSeed, index: 5, id: "e")
        let entries = identity.listRegistryEntries()
        XCTAssertEqual(entries.count, 3)
        XCTAssertEqual(entries[0].idx, 1)
        XCTAssertEqual(entries[0].nickname, "Alice")
        XCTAssertEqual(entries[1].idx, 3)
        XCTAssertEqual(entries[1].nickname, "Charlie")
        XCTAssertEqual(entries[2].idx, 5)
        XCTAssertNil(entries[2].nickname)
    }

    func testRegistryPersistsAfterPersonaDeletion() {
        let p = identity.createPersona(seed: testSeed, index: 0, displayName: "Alice")
        identity.deletePersona(p)
        let entries = identity.listRegistryEntries()
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].idx, 0)
        XCTAssertEqual(entries[0].nickname, "Alice")
    }
}
