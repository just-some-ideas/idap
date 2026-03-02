import Foundation
import Combine
import IDAPCrypto

@MainActor
final class OnboardingViewModel: ObservableObject {
    enum Step {
        case welcome
        case recoveryPhrase
        case complete
    }

    @Published var step: Step = .welcome
    @Published var mnemonicWords: [String] = []
    @Published var verificationIndices: [Int] = []
    @Published var verificationAnswers: [Int: String] = [:]
    @Published var verificationFailed: Bool = false
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?

    private let crypto: CryptoProviding
    private let keychain: KeychainProviding
    private let session: IDAPSession

    private var generatedSeed: Data?

    init(
        crypto: CryptoProviding,
        keychain: KeychainProviding,
        session: IDAPSession
    ) {
        self.crypto = crypto
        self.keychain = keychain
        self.session = session
    }

    // MARK: - Step navigation

    func proceedFromWelcome() {
        generateAndStoreSeed()
        step = .recoveryPhrase
    }

    func resetVerification() {
        verificationIndices = Array(Set((0..<mnemonicWords.count).shuffled().prefix(4))).sorted()
        verificationAnswers = [:]
        verificationFailed = false
    }

    func skipRecoveryPhrase() {
        step = .complete
    }

    func confirmRecoveryPhrase() {
        let correct = verificationIndices.allSatisfy { idx in
            verificationAnswers[idx]?.lowercased().trimmingCharacters(in: .whitespaces) == mnemonicWords[idx].lowercased()
        }
        if correct {
            step = .complete
        } else {
            verificationFailed = true
        }
    }

    func completeOnboarding() {
        session.markOnboarded()
    }

    // MARK: - Seed generation and encryption

    private func generateAndStoreSeed() {
        let seed = crypto.generateMasterSeed()
        generatedSeed = seed
        mnemonicWords = crypto.seedToMnemonic(seed)
        verificationIndices = Array(Set((0..<24).shuffled().prefix(4))).sorted()

        #if targetEnvironment(simulator)
        // Simulator: store seed unencrypted (no Secure Enclave available)
        try? keychain.saveSeedCiphertext(seed)
        #else
        // Real device: Secure Enclave encryption
        if let enclaveKey = crypto.generateEnclaveKey(label: "idap.master"),
           let ciphertext = crypto.enclaveEncrypt(label: "idap.master", data: seed) {
            _ = enclaveKey
            try? keychain.saveSeedCiphertext(ciphertext)
        }
        #endif
    }
}
