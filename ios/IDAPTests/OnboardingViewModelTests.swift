import XCTest
import IDAPIdentity
@testable import IDAP

@MainActor
final class OnboardingViewModelTests: XCTestCase {
    private var crypto: MockCrypto!
    private var keychain: MockKeychain!
    private var session: IDAPSession!
    private var viewModel: OnboardingViewModel!

    override func setUp() async throws {
        crypto = MockCrypto()
        keychain = MockKeychain()
        session = try makeSession()
        viewModel = OnboardingViewModel(
            crypto: crypto,
            keychain: keychain,
            session: session
        )
    }

    func testProceedFromWelcomeGeneratesSeed() {
        viewModel.proceedFromWelcome()

        XCTAssertTrue(crypto.generateSeedCalled, "Seed should be generated after proceeding from welcome")
        XCTAssertFalse(keychain.saveCalledFor.isEmpty, "Seed ciphertext should be stored in keychain")
        XCTAssertEqual(viewModel.step, .recoveryPhrase)
    }

    func testSkipRecoveryPhraseAllowed() {
        viewModel.proceedFromWelcome()
        viewModel.skipRecoveryPhrase()

        XCTAssertEqual(viewModel.step, .complete)
    }

    // MARK: - Helpers

    private func makeSession() throws -> IDAPSession {
        return IDAPSession()
    }
}
