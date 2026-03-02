import Foundation
import Combine
import LocalAuthentication
import IDAPAuth
import IDAPIdentity

@MainActor
final class AuthApprovalViewModel: ObservableObject {
    enum ApprovalState: Equatable {
        case pending
        case authenticating
        case approved
        case denied
        case expired
        case flagged
    }

    @Published var state: ApprovalState = .pending
    @Published var secondsRemaining: Int = 30
    @Published var errorMessage: String?

    let request: AuthRequest

    var activePersonaLabel: String {
        session.activePersona?.displayLabel ?? request.personaHint ?? ""
    }

    private let auth: AuthProviding
    private let session: IDAPSession
    private var timerCancellable: AnyCancellable?

    init(request: AuthRequest, auth: AuthProviding, session: IDAPSession) {
        self.request = request
        self.auth = auth
        self.session = session

        calculateTimeRemaining()
        startTimer()
    }

    // MARK: - Actions

    func approve() async {
        guard state == .pending else { return }
        guard let persona = session.activePersona, let seed = session.seed else {
            errorMessage = "No active persona."
            return
        }

        state = .authenticating
        var authSuccess = false

        #if targetEnvironment(simulator)
        authSuccess = true
        #else
        let context = LAContext()
        do {
            authSuccess = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Approve login to \(request.serviceDisplayName)"
            )
        } catch {
            // Biometrics unavailable — fall back to device passcode
            let fallback = LAContext()
            authSuccess = (try? await fallback.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Approve login to \(request.serviceDisplayName)"
            )) ?? false
        }
        #endif

        guard authSuccess else {
            state = .pending
            return
        }

        let assertion = auth.approveAuthRequest(request, persona: persona, seed: seed)

        session.activityStore.log(ActivityEvent(
            personaId: persona.id,
            personaLabel: persona.displayLabel,
            serviceName: request.serviceDisplayName,
            approved: true,
            scopes: request.requesting,
            requestId: request.requestId
        ))

        do {
            if let ws = session.wsSession, ws.connector.isConnected {
                try ws.submitAssertion(assertion)
            } else {
                try await postAssertionToProxy(assertion: assertion, persona: persona)
            }
            timerCancellable?.cancel()
            state = .approved
            session.pendingAuthRequest = nil
        } catch {
            errorMessage = "Failed to submit: \(error.localizedDescription)"
            state = .pending
        }
    }

    func deny() {
        auth.denyAuthRequest(request)
        logActivity(approved: false)
        timerCancellable?.cancel()
        state = .denied
        session.pendingAuthRequest = nil
    }

    func reportSuspicious() {
        auth.denyAuthRequest(request)
        logActivity(approved: false)
        timerCancellable?.cancel()
        state = .flagged
        session.pendingAuthRequest = nil
    }

    // MARK: - Timer

    private func calculateTimeRemaining() {
        secondsRemaining = max(0, Int(request.expiresAt.timeIntervalSinceNow))
        if secondsRemaining == 0 { state = .expired }
    }

    private func startTimer() {
        guard state != .expired else { return }
        timerCancellable = Timer.publish(every: 1, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                guard let self, self.state == .pending else { return }
                if self.secondsRemaining > 0 {
                    self.secondsRemaining -= 1
                } else {
                    self.timerCancellable?.cancel()
                    self.state = .expired
                }
            }
    }

    // MARK: - Private

    private func logActivity(approved: Bool) {
        guard let persona = session.activePersona else { return }
        session.activityStore.log(ActivityEvent(
            personaId: persona.id,
            personaLabel: persona.displayLabel,
            serviceName: request.serviceDisplayName,
            approved: approved,
            scopes: request.requesting,
            requestId: request.requestId
        ))
    }

    private func postAssertionToProxy(assertion: SignedAssertion, persona: Persona) async throws {
        guard let proxy = persona.primaryProxy else { throw URLError(.badURL) }
        let url = proxy.appendingPathComponent("auth/assert")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = ["jwt": assertion.jwt, "requestId": assertion.requestId]
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        let (_, response) = try await URLSession.shared.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode < 300 else {
            throw URLError(.badServerResponse)
        }
    }
}
