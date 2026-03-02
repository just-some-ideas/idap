import Foundation
import Combine
import IDAPContacts
import IDAPIdentity

@MainActor
final class ContactsViewModel: ObservableObject {
    @Published var contacts: [Contact] = []
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    @Published var activeAccessCode: AccessCode?
    @Published var secondsRemaining: Int = 0
    @Published var codeEntryText: String = ""

    private var contactsProvider: ContactsProviding
    private let session: IDAPSession
    private var timerCancellable: AnyCancellable?

    init(contactsProvider: ContactsProviding, session: IDAPSession) {
        self.contactsProvider = contactsProvider
        self.session = session
    }

    func loadContacts() {
        activeAccessCode = nil
        timerCancellable?.cancel()
        secondsRemaining = 0
        codeEntryText = ""
        errorMessage = nil

        guard let persona = session.activePersona else {
            contacts = []
            return
        }
        contacts = contactsProvider.listContacts(persona: persona)
    }

    func removeContact(_ contact: Contact) {
        contactsProvider.removeContact(contact)
        loadContacts()
    }

    // MARK: - Access Code (Share)

    var availableProxies: [URL] {
        session.activePersona?.proxies ?? []
    }

    var defaultProxy: URL? {
        session.activePersona?.primaryProxy
    }

    func generateAccessCode(proxyURL: URL? = nil) async {
        isLoading = true
        defer { isLoading = false }
        do {
            let code = try await session.generateAccessCode(proxyURL: proxyURL)
            activeAccessCode = code
            secondsRemaining = code.expiresIn
            startTimer()
        } catch {
            errorMessage = "Failed to generate code: \(error.localizedDescription)"
        }
    }

    // MARK: - Code Entry

    func handleIncomingCode(_ code: String, proxyURL: URL? = nil) async {
        guard let persona = session.activePersona else { return }
        isLoading = true
        defer { isLoading = false }
        guard let proxy = proxyURL ?? persona.primaryProxy else { return }
        await session.handleIncomingCode(code, endpoint: proxy)
    }

    // MARK: - Deep Link

    func handleDeepLink(_ url: URL) async {
        session.handleDeepLink(url)
    }

    func connectDeepLink(proxyURL: URL? = nil) -> URL? {
        guard let code = activeAccessCode?.code,
              let persona = session.activePersona else { return nil }
        guard let proxy = proxyURL ?? persona.primaryProxy else { return nil }
        let proxyEncoded = proxy.absoluteString
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        return URL(string: "idap://connect?endpoint=\(proxyEncoded)&code=\(code)")
    }

    // MARK: - Private

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
                    self.activeAccessCode = nil
                }
            }
    }
}
