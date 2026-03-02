import SwiftUI

struct OnboardingCoordinatorView: View {
    let session: IDAPSession
    @StateObject private var viewModel: OnboardingViewModel
    @State private var showPersonaCreation: Bool = false

    init(session: IDAPSession) {
        self.session = session
        _viewModel = StateObject(wrappedValue: OnboardingViewModel(
            crypto: IDAPCryptoService(),
            keychain: session.keychain,
            session: session
        ))
    }

    var body: some View {
        NavigationStack {
            content
        }
        .fullScreenCover(isPresented: $showPersonaCreation) {
            CreatePersonaView(session: session, isInitialPersona: true)
        }
    }

    @ViewBuilder
    private var content: some View {
        switch viewModel.step {
        case .welcome:
            WelcomeView { viewModel.proceedFromWelcome() }
        case .recoveryPhrase:
            RecoveryPhraseView(viewModel: viewModel)
        case .complete:
            OnboardingCompleteView(viewModel: viewModel) {
                showPersonaCreation = true
            }
        }
    }
}
