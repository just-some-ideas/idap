// IDAPContacts — X3DH contact exchange, encrypted contact book, shard distribution
// Depends on: IDAPCrypto, IDAPIdentity, GRDB

import CryptoKit
import Foundation
import GRDB
import IDAPCrypto
import IDAPIdentity

// MARK: - Key Bundle

/// Public-facing key bundle shared with the proxy / other users.
public struct ContactKeyBundle: Codable, Equatable {
    public let personaId: String
    /// X25519 long-term identity public key.
    public let identityPublicKey: Data
    /// X25519 signed pre-key (medium-term). Signed by persona's Ed25519 key.
    public let signedPreKey: Data
    /// Ed25519 signature of `signedPreKey` using persona's signing key.
    public let signedPreKeySignature: Data
    /// X25519 one-time pre-keys (consumed once per exchange).
    public let oneTimePreKeys: [Data]

    public init(personaId: String, identityPublicKey: Data, signedPreKey: Data,
                signedPreKeySignature: Data, oneTimePreKeys: [Data]) {
        self.personaId = personaId
        self.identityPublicKey = identityPublicKey
        self.signedPreKey = signedPreKey
        self.signedPreKeySignature = signedPreKeySignature
        self.oneTimePreKeys = oneTimePreKeys
    }
}

/// Private key material (stored locally, never shared).
public struct ContactKeyBundlePrivate {
    public let bundle: ContactKeyBundle
    public let identityPrivateKey: Data
    public let signedPreKeyPrivate: Data
    public let oneTimePreKeyPrivates: [Data]

    public init(bundle: ContactKeyBundle, identityPrivateKey: Data,
                signedPreKeyPrivate: Data, oneTimePreKeyPrivates: [Data]) {
        self.bundle = bundle
        self.identityPrivateKey = identityPrivateKey
        self.signedPreKeyPrivate = signedPreKeyPrivate
        self.oneTimePreKeyPrivates = oneTimePreKeyPrivates
    }
}

/// Output of a successful X3DH initiation.
public struct X3DHResult {
    public let sharedSecret: Data
    public let ephemeralPublicKey: Data
    public let usedOneTimePreKeyIndex: Int?

    public init(sharedSecret: Data, ephemeralPublicKey: Data, usedOneTimePreKeyIndex: Int?) {
        self.sharedSecret = sharedSecret
        self.ephemeralPublicKey = ephemeralPublicKey
        self.usedOneTimePreKeyIndex = usedOneTimePreKeyIndex
    }
}

// MARK: - Contact Card & Contact

public struct ContactCard: Codable, Equatable {
    public let publicKey: Data
    public let identityPublicKey: Data
    public var displayName: String?
    public var email: String?
    public var phone: String?
    public var avatarHash: String?

    public init(publicKey: Data, identityPublicKey: Data, displayName: String? = nil,
                email: String? = nil, phone: String? = nil, avatarHash: String? = nil) {
        self.publicKey = publicKey
        self.identityPublicKey = identityPublicKey
        self.displayName = displayName
        self.email = email
        self.phone = phone
        self.avatarHash = avatarHash
    }
}

public struct Contact: Equatable {
    public let id: String
    public let personaId: String
    public let publicKey: Data
    public let identityPublicKey: Data
    public let sharedSecret: Data
    public var displayName: String?
    public var email: String?
    public var phone: String?
    public var avatarHash: String?
    public var holdsShardId: String?

    public init(id: String, personaId: String, publicKey: Data,
                identityPublicKey: Data, sharedSecret: Data,
                displayName: String? = nil, email: String? = nil,
                phone: String? = nil, avatarHash: String? = nil,
                holdsShardId: String? = nil) {
        self.id = id; self.personaId = personaId; self.publicKey = publicKey
        self.identityPublicKey = identityPublicKey; self.sharedSecret = sharedSecret
        self.displayName = displayName; self.email = email; self.phone = phone
        self.avatarHash = avatarHash; self.holdsShardId = holdsShardId
    }
}

// MARK: - PII Field

public enum ContactField: String, Codable, Equatable {
    case name, email, phone, avatar
}

public struct FieldUpdate: Equatable {
    public let field: ContactField
    public let value: String?  // nil = revocation

    public init(field: ContactField, value: String?) {
        self.field = field; self.value = value
    }
}

// MARK: - Encrypted Shard

public struct EncryptedShard: Equatable {
    public let ciphertext: Data
    public let nonce: Data
    public let tag: Data
    public let ephemeralPublicKey: Data

    public init(ciphertext: Data, nonce: Data, tag: Data, ephemeralPublicKey: Data) {
        self.ciphertext = ciphertext; self.nonce = nonce; self.tag = tag
        self.ephemeralPublicKey = ephemeralPublicKey
    }
}

// MARK: - Capability Types

/// Describes where to send a reply (the sender's inbox endpoint + access proof).
public struct ReplyPath: Codable, Equatable {
    public let endpoint: URL
    public let pubkey: Data
    public let accessCode: String?
    public let accessProof: String?
    public let agreementKey: WireTypedKey?

    public init(endpoint: URL, pubkey: Data, accessCode: String? = nil, accessProof: String? = nil, agreementKey: WireTypedKey? = nil) {
        self.endpoint = endpoint; self.pubkey = pubkey
        self.accessCode = accessCode; self.accessProof = accessProof
        self.agreementKey = agreementKey
    }
}

/// What PII the requester wants.
public struct PIIFieldRequest: Codable, Equatable {
    public let field: ContactField
    public let reason: String?

    public init(field: ContactField, reason: String? = nil) {
        self.field = field; self.reason = reason
    }
}

/// The access being requested.
public struct RequestedAccess: Codable, Equatable {
    public let messageTypes: [String]
    public let categories: [String]
    public let piiFields: [PIIFieldRequest]?

    public init(messageTypes: [String] = [], categories: [String] = [], piiFields: [PIIFieldRequest]? = nil) {
        self.messageTypes = messageTypes; self.categories = categories; self.piiFields = piiFields
    }
}

/// A capability request sent by the initiator.
public struct CapabilityRequest: Codable, Equatable {
    public let requestId: String
    public let requestedAccess: RequestedAccess
    public let replyPath: ReplyPath
    public let identity: [String: String]?
    public let timestamp: Double

    public init(requestId: String, requestedAccess: RequestedAccess,
                replyPath: ReplyPath, identity: [String: String]? = nil,
                timestamp: Double = Date().timeIntervalSince1970) {
        self.requestId = requestId; self.requestedAccess = requestedAccess
        self.replyPath = replyPath; self.identity = identity; self.timestamp = timestamp
    }
}

/// The access being granted.
public struct GrantedAccess: Codable, Equatable {
    public let messageTypes: [String]
    public let categories: [String]
    public let expiresAt: Double?

    public init(messageTypes: [String] = [], categories: [String] = [], expiresAt: Double? = nil) {
        self.messageTypes = messageTypes; self.categories = categories; self.expiresAt = expiresAt
    }
}

/// A capability grant sent by the recipient.
public struct CapabilityGrant: Codable, Equatable {
    public let grantId: String
    public let requestId: String
    public let grantedAccess: GrantedAccess
    public let replyPath: ReplyPath?
    public let timestamp: Double

    public init(grantId: String, requestId: String, grantedAccess: GrantedAccess,
                replyPath: ReplyPath? = nil,
                timestamp: Double = Date().timeIntervalSince1970) {
        self.grantId = grantId; self.requestId = requestId
        self.grantedAccess = grantedAccess; self.replyPath = replyPath; self.timestamp = timestamp
    }
}

/// A denial of a capability request.
public struct CapabilityDenial: Codable, Equatable {
    public let requestId: String
    public let reason: String?
    public let timestamp: Double

    public init(requestId: String, reason: String? = nil,
                timestamp: Double = Date().timeIntervalSince1970) {
        self.requestId = requestId; self.reason = reason; self.timestamp = timestamp
    }
}

/// Revocation of a previously granted capability.
public struct CapabilityRevocation: Codable, Equatable {
    public let grantId: String
    public let reason: String?
    public let timestamp: Double

    public init(grantId: String, reason: String? = nil,
                timestamp: Double = Date().timeIntervalSince1970) {
        self.grantId = grantId; self.reason = reason; self.timestamp = timestamp
    }
}

/// Header of an inbox message (always present, decryptable by recipient).
public struct MessageHeader: Codable, Equatable {
    public let type: String
    public let senderPubkey: Data?
    public let ephemeralPublicKey: Data
    public let timestamp: Double

    public init(type: String, senderPubkey: Data? = nil,
                ephemeralPublicKey: Data,
                timestamp: Double = Date().timeIntervalSince1970) {
        self.type = type; self.senderPubkey = senderPubkey
        self.ephemeralPublicKey = ephemeralPublicKey; self.timestamp = timestamp
    }
}

/// Typed inbox message after decryption.
public enum InboxMessage: Equatable {
    case capabilityRequest(CapabilityRequest)
    case capabilityGrant(CapabilityGrant)
    case capabilityDenial(CapabilityDenial)
    case capabilityRevocation(CapabilityRevocation)
    case contactCard(ContactCard)
    case unknown(String)
}

// MARK: - Access Code Client Types

/// Response from generating an access code.
public struct AccessCode: Codable, Equatable {
    public let code: String
    public let expiresIn: Int

    public init(code: String, expiresIn: Int) {
        self.code = code; self.expiresIn = expiresIn
    }

    enum CodingKeys: String, CodingKey {
        case code
        case expiresIn = "expires_in"
    }
}

/// Response from resolving an access code.
public struct ResolvedCode: Codable, Equatable {
    public let pubkey: String
    public let keyBundle: KeyBundleResponse

    public init(pubkey: String, keyBundle: KeyBundleResponse) {
        self.pubkey = pubkey; self.keyBundle = keyBundle
    }

    enum CodingKeys: String, CodingKey {
        case pubkey
        case keyBundle = "key_bundle"
    }
}

/// Typed key as returned by the proxy: `{"kty":"ed25519","key":"<base64url>"}`.
public struct WireTypedKey: Codable, Equatable {
    public let kty: String
    public let key: String

    public init(kty: String, key: String) {
        self.kty = kty; self.key = key
    }

    /// Decode the raw key bytes from the base64url-encoded `key` field.
    public func decode() -> Data? {
        Data(base64URLEncoded: key)
    }
}

/// The key bundle as returned by the proxy (V2 typed format).
public struct KeyBundleResponse: Codable, Equatable {
    public let signingKey: WireTypedKey
    public let agreementKey: WireTypedKey
    public let signedPreKey: WireTypedKey?
    public let oneTimePreKeys: [WireTypedKey]?

    public init(signingKey: WireTypedKey, agreementKey: WireTypedKey,
                signedPreKey: WireTypedKey? = nil, oneTimePreKeys: [WireTypedKey]? = nil) {
        self.signingKey = signingKey; self.agreementKey = agreementKey
        self.signedPreKey = signedPreKey; self.oneTimePreKeys = oneTimePreKeys
    }

    enum CodingKeys: String, CodingKey {
        case signingKey = "signing_key"
        case agreementKey = "agreement_key"
        case signedPreKey = "signed_pre_key"
        case oneTimePreKeys = "one_time_pre_keys"
    }
}

// MARK: - Capability Grant Storage

public struct StoredGrant: Codable, Equatable {
    public let grantId: String
    public let personaId: String
    public let peerPubkey: Data
    public let peerEndpoint: URL
    public let accessProof: String?
    public let grantedMessageTypes: [String]
    public let grantedCategories: [String]
    public let expiresAt: Double?
    public let direction: String  // "inbound" or "outbound"

    public init(grantId: String, personaId: String, peerPubkey: Data, peerEndpoint: URL,
                accessProof: String? = nil, grantedMessageTypes: [String] = [],
                grantedCategories: [String] = [], expiresAt: Double? = nil,
                direction: String) {
        self.grantId = grantId; self.personaId = personaId; self.peerPubkey = peerPubkey
        self.peerEndpoint = peerEndpoint; self.accessProof = accessProof
        self.grantedMessageTypes = grantedMessageTypes; self.grantedCategories = grantedCategories
        self.expiresAt = expiresAt; self.direction = direction
    }
}

// MARK: - GRDB Grant Row

private struct GrantRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "capability_grants"
    var grantId: String
    var personaId: String
    var peerPubkey: Data
    var peerEndpoint: String
    var accessProof: String?
    var grantedMessageTypes: String  // JSON array
    var grantedCategories: String    // JSON array
    var expiresAt: Double?
    var direction: String

    func toStoredGrant() -> StoredGrant? {
        guard let url = URL(string: peerEndpoint) else { return nil }
        let msgTypes = (try? JSONDecoder().decode([String].self, from: Data(grantedMessageTypes.utf8))) ?? []
        let cats = (try? JSONDecoder().decode([String].self, from: Data(grantedCategories.utf8))) ?? []
        return StoredGrant(grantId: grantId, personaId: personaId, peerPubkey: peerPubkey,
                           peerEndpoint: url, accessProof: accessProof,
                           grantedMessageTypes: msgTypes, grantedCategories: cats,
                           expiresAt: expiresAt, direction: direction)
    }

    static func from(_ g: StoredGrant) -> GrantRow {
        let msgTypesJSON = (try? String(data: JSONEncoder().encode(g.grantedMessageTypes), encoding: .utf8)) ?? "[]"
        let catsJSON = (try? String(data: JSONEncoder().encode(g.grantedCategories), encoding: .utf8)) ?? "[]"
        return GrantRow(grantId: g.grantId, personaId: g.personaId, peerPubkey: g.peerPubkey,
                        peerEndpoint: g.peerEndpoint.absoluteString, accessProof: g.accessProof,
                        grantedMessageTypes: msgTypesJSON, grantedCategories: catsJSON,
                        expiresAt: g.expiresAt, direction: g.direction)
    }
}

// MARK: - GRDB Contact Row

private struct ContactRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "contacts"
    var id: String
    var personaId: String
    var publicKey: Data
    var identityPublicKey: Data
    var sharedSecret: Data
    var displayName: String?
    var email: String?
    var phone: String?
    var avatarHash: String?
    var holdsShardId: String?

    func toContact() -> Contact {
        Contact(id: id, personaId: personaId, publicKey: publicKey,
                identityPublicKey: identityPublicKey, sharedSecret: sharedSecret,
                displayName: displayName, email: email, phone: phone,
                avatarHash: avatarHash, holdsShardId: holdsShardId)
    }

    static func from(_ c: Contact) -> ContactRow {
        ContactRow(id: c.id, personaId: c.personaId, publicKey: c.publicKey,
                   identityPublicKey: c.identityPublicKey, sharedSecret: c.sharedSecret,
                   displayName: c.displayName, email: c.email, phone: c.phone,
                   avatarHash: c.avatarHash, holdsShardId: c.holdsShardId)
    }
}

// MARK: - IDAPContacts

public final class IDAPContacts {

    private let db: DatabaseQueue

    public init(db: DatabaseQueue) throws {
        self.db = db
        try applyMigrations()
    }

    public static func inMemory() throws -> IDAPContacts {
        try IDAPContacts(db: DatabaseQueue())
    }

    private func applyMigrations() throws {
        try db.write { db in
            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS contacts (
                    id TEXT PRIMARY KEY,
                    personaId TEXT NOT NULL,
                    publicKey BLOB NOT NULL,
                    identityPublicKey BLOB NOT NULL,
                    sharedSecret BLOB NOT NULL,
                    displayName TEXT,
                    email TEXT,
                    phone TEXT,
                    avatarHash TEXT,
                    holdsShardId TEXT
                );
            """)
            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS capability_grants (
                    grantId TEXT PRIMARY KEY,
                    personaId TEXT NOT NULL,
                    peerPubkey BLOB NOT NULL,
                    peerEndpoint TEXT NOT NULL,
                    accessProof TEXT,
                    grantedMessageTypes TEXT NOT NULL DEFAULT '[]',
                    grantedCategories TEXT NOT NULL DEFAULT '[]',
                    expiresAt REAL,
                    direction TEXT NOT NULL
                );
            """)
        }
    }

    // MARK: - X3DH Key Bundle Generation

    /// Generate a fresh key bundle for the given persona.
    /// Private keys are returned to the caller and must be stored securely.
    public func generateKeyBundle(persona: Persona, seed: Data, oneTimePreKeyCount: Int = 5) -> ContactKeyBundlePrivate {
        // Derive deterministic X25519 identity key from seed + persona index
        let ikSeed = IDAPCrypto.hkdf(secret: seed,
                                     salt: Data("idap-contact-identity".utf8),
                                     info: Data(persona.id.utf8),
                                     length: 32)
        let identityKP = IDAPCrypto.generateEphemeralX25519FromSeed(ikSeed)

        // Generate signed pre-key (random)
        let spkKP = IDAPCrypto.generateEphemeralX25519()

        // Sign the SPK with the persona's Ed25519 key
        let personaKP = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        let spkSig = IDAPCrypto.sign(privateKey: personaKP.privateKey, message: spkKP.publicKey)

        // Generate one-time pre-keys (random)
        var otpPrivates: [Data] = []
        var otpPublics: [Data] = []
        for _ in 0..<oneTimePreKeyCount {
            let kp = IDAPCrypto.generateEphemeralX25519()
            otpPrivates.append(kp.privateKey)
            otpPublics.append(kp.publicKey)
        }

        let bundle = ContactKeyBundle(
            personaId: persona.id,
            identityPublicKey: identityKP.publicKey,
            signedPreKey: spkKP.publicKey,
            signedPreKeySignature: spkSig,
            oneTimePreKeys: otpPublics
        )
        return ContactKeyBundlePrivate(bundle: bundle,
                                       identityPrivateKey: identityKP.privateKey,
                                       signedPreKeyPrivate: spkKP.privateKey,
                                       oneTimePreKeyPrivates: otpPrivates)
    }

    // MARK: - X3DH Initiation (Alice's side)

    /// Compute X3DH shared secret as the initiator.
    /// - Parameters:
    ///   - myBundle: caller's private key material
    ///   - theirBundle: recipient's public key bundle
    ///   - theirPersonaPublicKey: if provided, the SPK signature is verified
    /// - Returns: X3DHResult with shared secret and ephemeral public key to transmit, or nil if verification fails
    public func x3dhInitiate(
        myBundle: ContactKeyBundlePrivate,
        theirBundle: ContactKeyBundle,
        verifyWith theirPersonaPublicKey: Data? = nil
    ) -> X3DHResult? {
        // Optionally verify the signed pre-key
        if let pk = theirPersonaPublicKey {
            guard IDAPCrypto.verify(publicKey: pk,
                                    message: theirBundle.signedPreKey,
                                    signature: theirBundle.signedPreKeySignature) else { return nil }
        }

        let ephemeral = IDAPCrypto.generateEphemeralX25519()

        // DH1 = DH(IK_A, SPK_B)
        let dh1 = IDAPCrypto.deriveSharedSecret(myPrivate: myBundle.identityPrivateKey,
                                                 theirPublic: theirBundle.signedPreKey)
        // DH2 = DH(EK_A, IK_B)
        let dh2 = IDAPCrypto.deriveSharedSecret(myPrivate: ephemeral.privateKey,
                                                 theirPublic: theirBundle.identityPublicKey)
        // DH3 = DH(EK_A, SPK_B)
        let dh3 = IDAPCrypto.deriveSharedSecret(myPrivate: ephemeral.privateKey,
                                                 theirPublic: theirBundle.signedPreKey)

        var dhConcat = dh1 + dh2 + dh3
        var usedOTPIndex: Int? = nil

        // DH4 = DH(EK_A, OPK_B) if available
        if let otp = theirBundle.oneTimePreKeys.first {
            let dh4 = IDAPCrypto.deriveSharedSecret(myPrivate: ephemeral.privateKey, theirPublic: otp)
            dhConcat += dh4
            usedOTPIndex = 0
        }

        let sk = IDAPCrypto.hkdf(secret: dhConcat,
                                  salt: Data("X3DH".utf8),
                                  info: Data("idap-contact-v1".utf8),
                                  length: 32)
        return X3DHResult(sharedSecret: sk, ephemeralPublicKey: ephemeral.publicKey,
                          usedOneTimePreKeyIndex: usedOTPIndex)
    }

    // MARK: - X3DH Response (Bob's side)

    /// Compute X3DH shared secret as the recipient.
    /// - Parameters:
    ///   - myBundle: own private key material
    ///   - initiatorIdentityPublicKey: initiator's long-term identity public key
    ///   - ephemeralPublicKey: initiator's ephemeral public key (from init message)
    ///   - usedOneTimePreKeyIndex: which OTP key was consumed
    /// - Returns: Shared secret, or nil if key index is out of range
    public func x3dhRespond(
        myBundle: ContactKeyBundlePrivate,
        initiatorIdentityPublicKey: Data,
        ephemeralPublicKey: Data,
        usedOneTimePreKeyIndex: Int? = nil
    ) -> Data? {
        // DH1 = DH(SPK_B, IK_A)
        let dh1 = IDAPCrypto.deriveSharedSecret(myPrivate: myBundle.signedPreKeyPrivate,
                                                 theirPublic: initiatorIdentityPublicKey)
        // DH2 = DH(IK_B, EK_A)
        let dh2 = IDAPCrypto.deriveSharedSecret(myPrivate: myBundle.identityPrivateKey,
                                                 theirPublic: ephemeralPublicKey)
        // DH3 = DH(SPK_B, EK_A)
        let dh3 = IDAPCrypto.deriveSharedSecret(myPrivate: myBundle.signedPreKeyPrivate,
                                                 theirPublic: ephemeralPublicKey)

        var dhConcat = dh1 + dh2 + dh3

        if let idx = usedOneTimePreKeyIndex {
            guard idx < myBundle.oneTimePreKeyPrivates.count else { return nil }
            let dh4 = IDAPCrypto.deriveSharedSecret(myPrivate: myBundle.oneTimePreKeyPrivates[idx],
                                                     theirPublic: ephemeralPublicKey)
            dhConcat += dh4
        }

        return IDAPCrypto.hkdf(secret: dhConcat,
                                salt: Data("X3DH".utf8),
                                info: Data("idap-contact-v1".utf8),
                                length: 32)
    }

    // MARK: - Contact Card Encryption / Decryption

    public func encryptContactCard(_ card: ContactCard, sharedSecret: Data) -> Data? {
        guard let json = try? JSONEncoder().encode(card) else { return nil }
        let payload = IDAPCrypto.encrypt(key: sharedSecret, plaintext: json)
        // Serialize as: nonce(12) + tag(16) + ciphertext
        return payload.nonce + payload.tag + payload.ciphertext
    }

    public func decryptContactCard(_ data: Data, sharedSecret: Data) -> ContactCard? {
        guard data.count > 28 else { return nil }
        let nonce = Data(data[0..<12])
        let tag = Data(data[12..<28])
        let ciphertext = Data(data[28...])
        let payload = EncryptedPayload(ciphertext: ciphertext, nonce: nonce, tag: tag)
        guard let plaintext = IDAPCrypto.decrypt(key: sharedSecret, payload: payload) else { return nil }
        return try? JSONDecoder().decode(ContactCard.self, from: plaintext)
    }

    // MARK: - Contact Storage

    public func storeContact(_ contact: Contact) {
        try? db.write { db in try ContactRow.from(contact).save(db) }
    }

    public func listContacts(persona: Persona) -> [Contact] {
        let rows = (try? db.read { db in
            try ContactRow.filter(Column("personaId") == persona.id).fetchAll(db)
        }) ?? []
        return rows.map { $0.toContact() }
    }

    public func getContact(publicKey: Data, persona: Persona) -> Contact? {
        let row = try? db.read { db in
            try ContactRow
                .filter(Column("personaId") == persona.id && Column("publicKey") == publicKey)
                .fetchOne(db)
        }
        return row?.toContact()
    }

    public func removeContact(_ contact: Contact) {
        try? db.write { db in
            try db.execute(sql: "DELETE FROM contacts WHERE id = ?", arguments: [contact.id])
        }
    }

    public func updateContact(_ contact: Contact) {
        storeContact(contact)
    }

    // MARK: - PII Field Sharing

    public func encryptFieldUpdate(field: ContactField, value: String, sharedSecret: Data) -> Data? {
        let msg: [String: String] = ["field": field.rawValue, "value": value]
        guard let json = try? JSONEncoder().encode(msg) else { return nil }
        let payload = IDAPCrypto.encrypt(key: sharedSecret, plaintext: json)
        return payload.nonce + payload.tag + payload.ciphertext
    }

    public func encryptFieldRevocation(field: ContactField, sharedSecret: Data) -> Data? {
        let msg: [String: Any] = ["field": field.rawValue, "revoked": true]
        guard let json = try? JSONSerialization.data(withJSONObject: msg) else { return nil }
        let payload = IDAPCrypto.encrypt(key: sharedSecret, plaintext: json)
        return payload.nonce + payload.tag + payload.ciphertext
    }

    public func decryptFieldUpdate(_ data: Data, sharedSecret: Data) -> FieldUpdate? {
        guard data.count > 28 else { return nil }
        let nonce = Data(data[0..<12])
        let tag = Data(data[12..<28])
        let ciphertext = Data(data[28...])
        let payload = EncryptedPayload(ciphertext: ciphertext, nonce: nonce, tag: tag)
        guard let plaintext = IDAPCrypto.decrypt(key: sharedSecret, payload: payload),
              let dict = try? JSONSerialization.jsonObject(with: plaintext) as? [String: Any],
              let fieldStr = dict["field"] as? String,
              let field = ContactField(rawValue: fieldStr) else { return nil }

        let revoked = dict["revoked"] as? Bool ?? false
        if revoked { return FieldUpdate(field: field, value: nil) }
        let value = dict["value"] as? String
        return FieldUpdate(field: field, value: value)
    }

    // MARK: - Recovery Shard Distribution

    /// Encrypt a Shamir share for a contact using their X25519 identity key.
    /// Returns the encrypted shard with an ephemeral public key for decryption.
    public func encryptShardForContact(_ shard: Share, identityPublicKey: Data) -> EncryptedShard? {
        let ephemeral = IDAPCrypto.generateEphemeralX25519()
        let dh = IDAPCrypto.deriveSharedSecret(myPrivate: ephemeral.privateKey, theirPublic: identityPublicKey)
        let key = IDAPCrypto.hkdf(secret: dh, salt: Data("idap-shard-v1".utf8),
                                   info: Data("shard-encryption".utf8), length: 32)

        // Serialize shard: [id(1)] + [value bytes]
        let plaintext = Data([shard.id]) + shard.value
        let payload = IDAPCrypto.encrypt(key: key, plaintext: plaintext)

        return EncryptedShard(ciphertext: payload.ciphertext, nonce: payload.nonce,
                              tag: payload.tag, ephemeralPublicKey: ephemeral.publicKey)
    }

    /// Decrypt a Shamir share using our X25519 identity private key.
    public func decryptShardFromContact(_ encrypted: EncryptedShard, myPrivateKey: Data) -> Share? {
        let dh = IDAPCrypto.deriveSharedSecret(myPrivate: myPrivateKey,
                                               theirPublic: encrypted.ephemeralPublicKey)
        let key = IDAPCrypto.hkdf(secret: dh, salt: Data("idap-shard-v1".utf8),
                                   info: Data("shard-encryption".utf8), length: 32)

        let payload = EncryptedPayload(ciphertext: encrypted.ciphertext, nonce: encrypted.nonce,
                                       tag: encrypted.tag)
        guard let plaintext = IDAPCrypto.decrypt(key: key, payload: payload),
              plaintext.count >= 1 else { return nil }

        let id = plaintext[0]
        let value = Data(plaintext[1...])
        return Share(id: id, value: value)
    }

    // MARK: - Message Header Encryption

    /// Encrypt a message header for the recipient using first-message encryption.
    /// Returns (encryptedHeader, ephemeralPublicKey) or nil on failure.
    public func encryptMessageHeader(_ header: MessageHeader, recipientX25519PublicKey: Data) -> (encrypted: Data, ephemeralPublicKey: Data)? {
        guard let json = try? JSONEncoder().encode(header) else { return nil }
        let (encrypted, ephPub) = IDAPCrypto.encryptForRecipient(
            recipientX25519PublicKey: recipientX25519PublicKey, plaintext: json)
        // Serialize: nonce(12) + tag(16) + ciphertext
        return (encrypted.nonce + encrypted.tag + encrypted.ciphertext, ephPub)
    }

    /// Decrypt a message header.
    public func decryptMessageHeader(encryptedHeader: Data, myPrivateKey: Data, ephemeralPublicKey: Data) -> MessageHeader? {
        guard encryptedHeader.count > 28 else { return nil }
        let nonce = Data(encryptedHeader[0..<12])
        let tag = Data(encryptedHeader[12..<28])
        let ciphertext = Data(encryptedHeader[28...])
        let payload = EncryptedPayload(ciphertext: ciphertext, nonce: nonce, tag: tag)
        guard let plaintext = IDAPCrypto.decryptFromSender(
            myX25519PrivateKey: myPrivateKey, ephemeralPublicKey: ephemeralPublicKey,
            payload: payload) else { return nil }
        return try? JSONDecoder().decode(MessageHeader.self, from: plaintext)
    }

    /// Decrypt a message payload and return a typed InboxMessage.
    public func decryptMessagePayload(type: String, encryptedPayload: Data, myPrivateKey: Data, ephemeralPublicKey: Data) -> InboxMessage? {
        guard encryptedPayload.count > 28 else { return nil }
        let nonce = Data(encryptedPayload[0..<12])
        let tag = Data(encryptedPayload[12..<28])
        let ciphertext = Data(encryptedPayload[28...])
        let payload = EncryptedPayload(ciphertext: ciphertext, nonce: nonce, tag: tag)
        guard let plaintext = IDAPCrypto.decryptFromSender(
            myX25519PrivateKey: myPrivateKey, ephemeralPublicKey: ephemeralPublicKey,
            payload: payload) else { return nil }

        switch type {
        case "capability_request":
            guard let req = try? JSONDecoder().decode(CapabilityRequest.self, from: plaintext) else { return nil }
            return .capabilityRequest(req)
        case "capability_grant":
            guard let grant = try? JSONDecoder().decode(CapabilityGrant.self, from: plaintext) else { return nil }
            return .capabilityGrant(grant)
        case "capability_denial":
            guard let denial = try? JSONDecoder().decode(CapabilityDenial.self, from: plaintext) else { return nil }
            return .capabilityDenial(denial)
        case "capability_revocation":
            guard let rev = try? JSONDecoder().decode(CapabilityRevocation.self, from: plaintext) else { return nil }
            return .capabilityRevocation(rev)
        case "contact_card":
            guard let card = try? JSONDecoder().decode(ContactCard.self, from: plaintext) else { return nil }
            return .contactCard(card)
        default:
            return .unknown(type)
        }
    }

    // MARK: - Capability Handshake

    /// Build a CapabilityRequest to send to a recipient.
    /// The caller must generate an access code for their own inbox to include as the reply path.
    public func buildCapabilityRequest(
        myPersona: Persona, seed: Data, myEndpoint: URL,
        myAccessCode: String, requestedAccess: RequestedAccess,
        identity: [String: String]? = nil
    ) -> CapabilityRequest {
        let personaKP = IDAPCrypto.derivePersonaKey(seed: seed, index: myPersona.derivationIndex)
        // Derive X25519 agreement key for the reply path
        let ikSeed = IDAPCrypto.hkdf(secret: seed,
                                     salt: Data("idap-contact-identity".utf8),
                                     info: Data(myPersona.id.utf8),
                                     length: 32)
        let agreementKP = IDAPCrypto.generateEphemeralX25519FromSeed(ikSeed)
        let agreementKey = WireTypedKey(kty: "x25519", key: agreementKP.publicKey.base64URLEncodedString())
        let replyPath = ReplyPath(endpoint: myEndpoint, pubkey: personaKP.publicKey,
                                  accessCode: myAccessCode, agreementKey: agreementKey)
        return CapabilityRequest(
            requestId: UUID().uuidString,
            requestedAccess: requestedAccess,
            replyPath: replyPath,
            identity: identity
        )
    }

    /// Build a CapabilityGrant in response to a request.
    public func buildCapabilityGrant(
        request: CapabilityRequest, grantedAccess: GrantedAccess,
        myPersona: Persona, seed: Data, myEndpoint: URL,
        myAccessCode: String? = nil, bidirectional: Bool = false
    ) -> CapabilityGrant {
        var replyPath: ReplyPath? = nil
        if bidirectional {
            let personaKP = IDAPCrypto.derivePersonaKey(seed: seed, index: myPersona.derivationIndex)
            replyPath = ReplyPath(endpoint: myEndpoint, pubkey: personaKP.publicKey,
                                  accessCode: myAccessCode)
        }
        return CapabilityGrant(
            grantId: UUID().uuidString,
            requestId: request.requestId,
            grantedAccess: grantedAccess,
            replyPath: replyPath
        )
    }

    /// Build a CapabilityDenial.
    public func buildCapabilityDenial(requestId: String, reason: String? = nil) -> CapabilityDenial {
        CapabilityDenial(requestId: requestId, reason: reason)
    }

    /// Build a CapabilityRevocation.
    public func buildCapabilityRevocation(grantId: String, reason: String? = nil) -> CapabilityRevocation {
        CapabilityRevocation(grantId: grantId, reason: reason)
    }

    // MARK: - Grant Storage

    public func storeGrant(_ grant: StoredGrant) {
        try? db.write { db in try GrantRow.from(grant).save(db) }
    }

    public func listGrants(persona: Persona) -> [StoredGrant] {
        let rows = (try? db.read { db in
            try GrantRow.filter(Column("personaId") == persona.id).fetchAll(db)
        }) ?? []
        return rows.compactMap { $0.toStoredGrant() }
    }

    public func getGrant(grantId: String) -> StoredGrant? {
        let row = try? db.read { db in
            try GrantRow.filter(Column("grantId") == grantId).fetchOne(db)
        }
        return row?.toStoredGrant()
    }

    public func revokeGrant(grantId: String) {
        try? db.write { db in
            try db.execute(sql: "DELETE FROM capability_grants WHERE grantId = ?", arguments: [grantId])
        }
    }
}
