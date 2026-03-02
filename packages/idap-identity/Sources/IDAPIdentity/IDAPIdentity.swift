// IDAPIdentity — persona management, credential wallet, signed records
// Depends on: IDAPCrypto, GRDB

import CryptoKit
import Foundation
import GRDB
import IDAPCrypto

// MARK: - Persona

public enum KeySource: String, Codable {
    case secureEnclave = "secure_enclave"
    case software = "software"
    case hardwareKey = "hardware_key"
}

public enum Reliability: String, Codable {
    case critical, bestEffort = "best_effort", relaxed
}

public struct PersonaProfile: Codable, Equatable {
    public var displayName: String?
    public var avatarHash: String?
    public var bio: String?
    public init(displayName: String? = nil, avatarHash: String? = nil, bio: String? = nil) {
        self.displayName = displayName
        self.avatarHash = avatarHash
        self.bio = bio
    }
}

public struct Persona: Equatable {
    public let id: String                // 'real' | 'gaming' | custom
    public let derivationIndex: UInt32
    public let publicKey: Data           // Ed25519 public key
    public var proxies: [URL]            // zero or more registered proxies
    public let reliability: Reliability
    public let keySource: KeySource
    public var publicProfile: PersonaProfile?

    /// First registered proxy, if any.
    public var primaryProxy: URL? { proxies.first }

    /// Human-readable label: display name if set, otherwise truncated base64 public key.
    public var displayLabel: String {
        publicProfile?.displayName ?? String(publicKey.base64EncodedString().prefix(8)) + "..."
    }

    public init(
        id: String,
        derivationIndex: UInt32,
        publicKey: Data,
        proxies: [URL] = [],
        reliability: Reliability = .bestEffort,
        keySource: KeySource = .software,
        publicProfile: PersonaProfile? = nil
    ) {
        self.id = id
        self.derivationIndex = derivationIndex
        self.publicKey = publicKey
        self.proxies = proxies
        self.reliability = reliability
        self.keySource = keySource
        self.publicProfile = publicProfile
    }
}

// MARK: - GRDB record for Persona

private struct PersonaRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "personas"
    var id: String
    var derivationIndex: Int64
    var publicKey: Data
    var proxy: String          // vestigial column, kept for migration compat
    var fallbackProxy: String? // vestigial
    var reliability: String
    var keySource: String
    var profileJSON: String?

    static func from(_ p: Persona) -> PersonaRow {
        let profile = p.publicProfile.flatMap { try? JSONEncoder().encode($0) }
        return PersonaRow(
            id: p.id,
            derivationIndex: Int64(p.derivationIndex),
            publicKey: p.publicKey,
            proxy: "",
            fallbackProxy: nil,
            reliability: p.reliability.rawValue,
            keySource: p.keySource.rawValue,
            profileJSON: profile.flatMap { String(data: $0, encoding: .utf8) }
        )
    }

    func toPersona(proxies: [URL]) -> Persona {
        let profile = profileJSON
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode(PersonaProfile.self, from: $0) }
        return Persona(
            id: id,
            derivationIndex: UInt32(derivationIndex),
            publicKey: publicKey,
            proxies: proxies,
            reliability: Reliability(rawValue: reliability) ?? .bestEffort,
            keySource: KeySource(rawValue: keySource) ?? .software,
            publicProfile: profile
        )
    }
}

private struct PersonaProxyRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "persona_proxies"
    var personaId: String
    var proxyURL: String
    var registeredAt: Int64
}

// MARK: - GRDB record for Derivation Registry

private struct DerivationRegistryRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "derivation_registry"
    var idx: Int64
    var nickname: String?
}

// MARK: - Credential

public struct Credential: Codable, Equatable {
    public let type: String
    public let issuer: String
    public let issuedTo: String
    public let issuanceDate: String
    public let credentialSubject: [String: String]
    public let raw: String  // original JSON

    public init(type: String, issuer: String, issuedTo: String, issuanceDate: String,
                credentialSubject: [String: String], raw: String) {
        self.type = type
        self.issuer = issuer
        self.issuedTo = issuedTo
        self.issuanceDate = issuanceDate
        self.credentialSubject = credentialSubject
        self.raw = raw
    }
}

private struct CredentialRow: Codable, FetchableRecord, PersistableRecord {
    static let databaseTableName = "credentials"
    var id: String         // UUID
    var personaId: String
    var type: String
    var json: String

    func toCredential() -> Credential? {
        guard let data = json.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        let typeArray = dict["type"] as? [String] ?? []
        // Use the most specific type (last non-VerifiableCredential entry, or last)
        let primaryType = typeArray.last(where: { $0 != "VerifiableCredential" }) ?? typeArray.last ?? type
        let issuer = dict["issuer"] as? String ?? ""
        let issuedTo = dict["issuedTo"] as? String ?? ""
        let issuanceDate = dict["issuanceDate"] as? String ?? ""
        let subjectDict = (dict["credentialSubject"] as? [String: Any] ?? [:])
            .compactMapValues { $0 as? String }
        return Credential(type: primaryType, issuer: issuer, issuedTo: issuedTo,
                         issuanceDate: issuanceDate, credentialSubject: subjectDict, raw: json)
    }
}

// MARK: - Signed Record

public struct UnsignedRecord {
    public let type: [String]
    public let issuer: String
    public let issuedTo: String
    public let credentialSubject: [String: Any]
    public init(type: [String], issuer: String, issuedTo: String, credentialSubject: [String: Any]) {
        self.type = type
        self.issuer = issuer
        self.issuedTo = issuedTo
        self.credentialSubject = credentialSubject
    }
}

public struct SignedRecord: Codable, Equatable {
    public let type: [String]
    public let issuer: String
    public let issuedTo: String
    public let issuanceDate: String
    public let credentialSubject: [String: String]
    public let proof: RecordProof
}

public struct RecordProof: Codable, Equatable {
    public let type: String
    public let verificationMethod: String
    public let signature: String
}

public struct VerifyResult {
    public let valid: Bool
    public let issuer: String
    public let subject: String
}

// MARK: - IDAPIdentity

public final class IDAPIdentity {

    private let db: DatabaseQueue

    public init(db: DatabaseQueue) throws {
        self.db = db
        try applyMigrations()
    }

    /// Create a new in-memory database (useful for tests).
    public static func inMemory() throws -> IDAPIdentity {
        let queue = try DatabaseQueue()
        return try IDAPIdentity(db: queue)
    }

    private func applyMigrations() throws {
        try db.write { db in
            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS personas (
                    id TEXT PRIMARY KEY,
                    derivationIndex INTEGER NOT NULL,
                    publicKey BLOB NOT NULL,
                    proxy TEXT NOT NULL DEFAULT '',
                    fallbackProxy TEXT,
                    reliability TEXT NOT NULL DEFAULT 'best_effort',
                    keySource TEXT NOT NULL DEFAULT 'software',
                    profileJSON TEXT
                );
                CREATE TABLE IF NOT EXISTS persona_proxies (
                    personaId TEXT NOT NULL,
                    proxyURL TEXT NOT NULL,
                    registeredAt INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (personaId, proxyURL)
                );
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY,
                    personaId TEXT NOT NULL,
                    type TEXT NOT NULL,
                    json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS derivation_registry (
                    idx INTEGER PRIMARY KEY,
                    nickname TEXT
                );
                INSERT OR IGNORE INTO derivation_registry (idx, nickname)
                SELECT derivationIndex, json_extract(profileJSON, '$.displayName')
                FROM personas;
                INSERT OR IGNORE INTO persona_proxies (personaId, proxyURL, registeredAt)
                SELECT id, proxy, 0 FROM personas WHERE proxy != '';
            """)
        }
    }

    // MARK: - Persona Lifecycle

    /// Create a new persona, deriving its public key from the master seed. Private key is NOT stored.
    public func createPersona(
        seed: Data,
        index: UInt32,
        id: String? = nil,
        displayName: String? = nil
    ) -> Persona {
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: index)
        let personaID = id ?? (index == 0 ? "real" : "persona-\(index)")
        let profile = displayName.map { PersonaProfile(displayName: $0) }
        let persona = Persona(
            id: personaID,
            derivationIndex: index,
            publicKey: kp.publicKey,
            publicProfile: profile
        )
        try? db.write { db in
            try DerivationRegistryRow(idx: Int64(index), nickname: displayName).save(db)
            try PersonaRow.from(persona).save(db)
        }
        return persona
    }

    public func listPersonas() -> [Persona] {
        (try? db.read { db in
            let rows = try PersonaRow.fetchAll(db)
            return rows.map { row -> Persona in
                let proxyRows = (try? PersonaProxyRow
                    .filter(Column("personaId") == row.id)
                    .fetchAll(db)) ?? []
                let proxies = proxyRows.compactMap { URL(string: $0.proxyURL) }
                return row.toPersona(proxies: proxies)
            }
        }) ?? []
    }

    /// Returns the next safe derivation index (max registry idx + 1, or 0 if none).
    /// Queries the derivation_registry table so indices are never reused, even after deletions.
    public func nextDerivationIndex() -> UInt32 {
        let maxIndex: Int64? = try? db.read { db in
            try Int64.fetchOne(db, sql: "SELECT MAX(idx) FROM derivation_registry")
        }
        guard let max = maxIndex else { return 0 }
        return UInt32(max + 1)
    }

    public func deletePersona(_ persona: Persona) {
        try? db.write { db in
            try db.execute(sql: "DELETE FROM personas WHERE id = ?", arguments: [persona.id])
            try db.execute(sql: "DELETE FROM credentials WHERE personaId = ?", arguments: [persona.id])
            try db.execute(sql: "DELETE FROM persona_proxies WHERE personaId = ?", arguments: [persona.id])
        }
    }

    // MARK: - Proxy Management

    public func registerProxy(_ url: URL, for persona: Persona) {
        let row = PersonaProxyRow(
            personaId: persona.id,
            proxyURL: url.absoluteString,
            registeredAt: Int64(Date().timeIntervalSince1970)
        )
        try? db.write { db in try row.save(db) }
    }

    public func removeProxy(_ url: URL, from persona: Persona) {
        try? db.write { db in
            try db.execute(
                sql: "DELETE FROM persona_proxies WHERE personaId = ? AND proxyURL = ?",
                arguments: [persona.id, url.absoluteString]
            )
        }
    }

    // MARK: - Profile

    public func updateProfile(_ profile: PersonaProfile, for persona: Persona) {
        guard let profileData = try? JSONEncoder().encode(profile),
              let profileJSON = String(data: profileData, encoding: .utf8) else { return }
        try? db.write { db in
            try db.execute(
                sql: "UPDATE personas SET profileJSON = ? WHERE id = ?",
                arguments: [profileJSON, persona.id]
            )
        }
    }

    // MARK: - Derivation Registry

    /// All ever-allocated derivation indices with their nicknames, ordered by index.
    public func listRegistryEntries() -> [(idx: UInt32, nickname: String?)] {
        let rows = (try? db.read { db in
            try DerivationRegistryRow.order(Column("idx")).fetchAll(db)
        }) ?? []
        return rows.map { (idx: UInt32($0.idx), nickname: $0.nickname) }
    }

    /// Set or clear the nickname for a registry entry.
    public func updateRegistryNickname(index: UInt32, nickname: String?) {
        try? db.write { db in
            try db.execute(
                sql: "UPDATE derivation_registry SET nickname = ? WHERE idx = ?",
                arguments: [nickname, Int64(index)]
            )
        }
    }

    /// Look up the nickname for a single derivation index.
    public func registryNickname(for index: UInt32) -> String? {
        try? db.read { db in
            try String.fetchOne(
                db,
                sql: "SELECT nickname FROM derivation_registry WHERE idx = ?",
                arguments: [Int64(index)]
            )
        }
    }

    // MARK: - On-Demand Key Derivation

    /// Derive the persona's key pair on demand. The caller is responsible for zeroing it after use.
    public func getPersonaKey(persona: Persona, seed: Data) -> KeyPair {
        IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
    }

    /// Derive key, execute the block, then zero the private key bytes from memory.
    public func withPersonaKey<T>(persona: Persona, seed: Data, block: (KeyPair) throws -> T) rethrows -> T {
        var kp = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        defer {
            // Zero private key — replace with a fresh zeroed Data
            kp = KeyPair(publicKey: kp.publicKey, privateKey: Data(count: kp.privateKey.count))
        }
        return try block(kp)
    }

    // MARK: - Credential Wallet

    public func storeCredential(_ credential: Credential, for persona: Persona) {
        let row = CredentialRow(
            id: UUID().uuidString,
            personaId: persona.id,
            type: credential.type,
            json: credential.raw
        )
        try? db.write { db in try row.save(db) }
    }

    public func listCredentials(for persona: Persona) -> [Credential] {
        let rows = (try? db.read { db in
            try CredentialRow.filter(Column("personaId") == persona.id).fetchAll(db)
        }) ?? []
        return rows.compactMap { $0.toCredential() }
    }

    public func getCredential(type: String, for persona: Persona) -> Credential? {
        let row = try? db.read { db in
            try CredentialRow
                .filter(Column("personaId") == persona.id && Column("type") == type)
                .fetchOne(db)
        }
        return row?.toCredential()
    }

    // MARK: - Signed Records (W3C Verifiable Credentials)

    /// Sign a record as this persona. Produces a W3C VC compatible signed record.
    public func signRecord(_ record: UnsignedRecord, persona: Persona, seed: Data) -> SignedRecord {
        let kp = IDAPCrypto.derivePersonaKey(seed: seed, index: persona.derivationIndex)
        let did = makeDID(publicKey: kp.publicKey)
        let dateString = ISO8601DateFormatter().string(from: Date())
            .prefix(10)
            .description  // "YYYY-MM-DD"

        // Build canonical representation of the unsigned payload
        let subjectStrings = record.credentialSubject.compactMapValues { $0 as? String }
        let canonical = canonicalJSON([
            "type": record.type,
            "issuer": did,
            "issuedTo": record.issuedTo,
            "issuanceDate": dateString,
            "credentialSubject": subjectStrings
        ])

        let sig = IDAPCrypto.sign(privateKey: kp.privateKey, message: Data(canonical.utf8))

        return SignedRecord(
            type: record.type,
            issuer: did,
            issuedTo: record.issuedTo,
            issuanceDate: dateString,
            credentialSubject: subjectStrings,
            proof: RecordProof(
                type: "Ed25519Signature2020",
                verificationMethod: did + "#signing-key",
                signature: sig.base64EncodedString()
            )
        )
    }

    /// Verify a signed record. Extracts the public key from the issuer DID.
    public func verifyRecord(_ record: SignedRecord) -> VerifyResult {
        guard let pubKeyData = pubKeyFromDID(record.issuer),
              let sig = Data(base64Encoded: record.proof.signature) else {
            return VerifyResult(valid: false, issuer: record.issuer, subject: record.issuedTo)
        }

        let canonical = canonicalJSON([
            "type": record.type,
            "issuer": record.issuer,
            "issuedTo": record.issuedTo,
            "issuanceDate": record.issuanceDate,
            "credentialSubject": record.credentialSubject
        ])

        let valid = IDAPCrypto.verify(
            publicKey: pubKeyData,
            message: Data(canonical.utf8),
            signature: sig
        )
        return VerifyResult(valid: valid, issuer: record.issuer, subject: record.issuedTo)
    }

    // MARK: - DID Helpers

    /// `did:idap:persona:<base58(sha256(publicKey))>`
    public static func makeDID(publicKey: Data) -> String {
        let hash = SHA256.hash(data: publicKey)
        let hashData = Data(hash)
        return "did:idap:persona:" + base58Encode(hashData)
    }

    func makeDID(publicKey: Data) -> String {
        IDAPIdentity.makeDID(publicKey: publicKey)
    }

    private func pubKeyFromDID(_ did: String) -> Data? {
        // DID format: did:idap:persona:<base58(sha256(pubKey))>
        // We cannot reverse SHA256, so we look up the persona in the DB
        guard did.hasPrefix("did:idap:persona:") else { return nil }
        let personas = listPersonas()
        for p in personas {
            if makeDID(publicKey: p.publicKey) == did {
                return p.publicKey
            }
        }
        return nil
    }

    // MARK: - Utilities

    private func canonicalJSON(_ value: Any) -> String {
        // Produce a deterministic JSON string (sorted keys at every level)
        func serialize(_ v: Any) -> String {
            if let dict = v as? [String: Any] {
                let pairs = dict.keys.sorted().map { key in
                    "\"\(key)\":\(serialize(dict[key]!))"
                }.joined(separator: ",")
                return "{\(pairs)}"
            } else if let arr = v as? [String] {
                let items = arr.map { "\"\($0)\"" }.joined(separator: ",")
                return "[\(items)]"
            } else if let arr = v as? [Any] {
                let items = arr.map { serialize($0) }.joined(separator: ",")
                return "[\(items)]"
            } else if let str = v as? String {
                return "\"\(str)\""
            } else {
                return "\(v)"
            }
        }
        return serialize(value)
    }

    // MARK: - Base58

    private static let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    static func base58Encode(_ data: Data) -> String {
        let leadingZeros = data.prefix(while: { $0 == 0 }).count
        // Treat the data as a big-endian unsigned integer; repeatedly divide by 58.
        // Use UInt32 per digit to avoid overflow when multiplying by 256.
        var num = data.map { UInt32($0) }  // big-endian base-256 digits
        var result = [Character]()

        while !num.allSatisfy({ $0 == 0 }) {
            var remainder: UInt32 = 0
            for i in 0..<num.count {
                let cur = remainder * 256 + num[i]
                num[i] = cur / 58
                remainder = cur % 58
            }
            result.insert(alphabet[Int(remainder)], at: result.startIndex)
        }
        let prefix = String(repeating: "1", count: leadingZeros)
        return prefix + String(result)
    }
}
