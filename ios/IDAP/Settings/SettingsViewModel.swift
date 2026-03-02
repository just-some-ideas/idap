import Foundation
import LocalAuthentication
import IDAPCrypto
import IDAPIdentity

@MainActor
final class SettingsViewModel: ObservableObject {
    @Published var mnemonicWords: [String] = []
    @Published var showingRecoveryPhrase: Bool = false
    @Published var errorMessage: String?
    @Published var successMessage: String?

    private let crypto: CryptoProviding
    private let keychain: KeychainProviding
    private let session: IDAPSession

    init(
        crypto: CryptoProviding,
        keychain: KeychainProviding,
        session: IDAPSession
    ) {
        self.crypto = crypto
        self.keychain = keychain
        self.session = session
    }

    func revealRecoveryPhrase() async {
        let context = LAContext()
        do {
            let granted = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Reveal your recovery phrase"
            )
            guard granted, let seed = session.seed else { return }
            mnemonicWords = crypto.seedToMnemonic(seed)
            showingRecoveryPhrase = true
        } catch {
            errorMessage = "Authentication required to reveal recovery phrase."
        }
    }

    var recoveryMap: String {
        guard let map = try? session.recovery.fetchRecoveryMap() else {
            return "No recovery map"
        }
        return "\(map.scheme) — \(map.entries.count) shard(s)"
    }
}
