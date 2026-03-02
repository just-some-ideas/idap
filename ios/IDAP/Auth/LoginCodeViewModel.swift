import Foundation
import Combine
import IDAPAuth

@MainActor
final class LoginCodeViewModel: ObservableObject {
    enum State: Equatable {
        case idle
        case loading
        case showing(code: String)
        case error(String)
    }

    @Published var state: State = .idle
    @Published var secondsRemaining: Int = 0

    private let session: IDAPSession
    private var timerCancellable: AnyCancellable?

    init(session: IDAPSession) {
        self.session = session
    }

    func requestCode(proxyURL: URL? = nil) async {
        state = .loading
        do {
            let loginCode = try await session.requestLoginCode(proxyURL: proxyURL)
            state = .showing(code: loginCode.code)
            secondsRemaining = loginCode.expiresIn
            startTimer()
        } catch {
            state = .error("Failed to generate code: \(error.localizedDescription)")
        }
    }

    private func startTimer() {
        timerCancellable?.cancel()
        timerCancellable = Timer.publish(every: 1, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self else { return }
                if self.secondsRemaining > 0 {
                    self.secondsRemaining -= 1
                } else {
                    self.timerCancellable?.cancel()
                    self.state = .idle
                }
            }
    }
}
