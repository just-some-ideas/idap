import XCTest
import IDAPContacts
import IDAPIdentity
import IDAPCrypto
@testable import IDAP

@MainActor
final class ContactsViewModelTests: XCTestCase {
    private var contactsProvider: MockContacts!
    private var session: IDAPSession!
    private var viewModel: ContactsViewModel!

    override func setUp() async throws {
        contactsProvider = MockContacts()
        session = IDAPSession()
        viewModel = ContactsViewModel(contactsProvider: contactsProvider, session: session)
    }

    func testEmptyStateShownWithNoContacts() {
        viewModel.loadContacts()
        XCTAssertTrue(viewModel.contacts.isEmpty)
    }

    func testContactListUpdatesAfterAdd() {
        let seed = Data(repeating: 0x42, count: 32)
        session.unlock(seed: seed)
        guard let persona = session.activePersona else { return }

        let kp = IDAPCrypto.generateEphemeralX25519()
        let contact = Contact(
            id: UUID().uuidString,
            personaId: persona.id,
            publicKey: kp.publicKey,
            identityPublicKey: kp.publicKey,
            sharedSecret: Data(repeating: 0, count: 32)
        )
        contactsProvider.contacts.append(contact)
        viewModel.loadContacts()

        XCTAssertEqual(viewModel.contacts.count, 1)
        XCTAssertEqual(viewModel.contacts.first?.publicKey, kp.publicKey)
    }

    func testDeepLinkTriggersContactInitiation() async {
        let url = URL(string: "idap://add?key=AAAA&proxy=https://idap.app")!
        await viewModel.handleDeepLink(url)
        // Verify no crash and loading completes
        XCTAssertFalse(viewModel.isLoading)
    }

    func testLoadContactsClearsAccessCodeState() {
        // Simulate active access code state
        viewModel.activeAccessCode = AccessCode(code: "ABC123", expiresIn: 300)
        viewModel.secondsRemaining = 250
        viewModel.codeEntryText = "XYZ"
        viewModel.errorMessage = "some error"

        viewModel.loadContacts()

        XCTAssertNil(viewModel.activeAccessCode)
        XCTAssertEqual(viewModel.secondsRemaining, 0)
        XCTAssertEqual(viewModel.codeEntryText, "")
        XCTAssertNil(viewModel.errorMessage)
    }

    func testContactsIsolatedBetweenPersonas() {
        // Two personas should have separate contact lists
        let seed = Data(repeating: 0x42, count: 32)
        session.unlock(seed: seed)

        // Add a contact for the first persona
        guard let persona1 = session.activePersona else { return }
        let kp1 = IDAPCrypto.generateEphemeralX25519()
        let contact1 = Contact(
            id: "c1",
            personaId: persona1.id,
            publicKey: kp1.publicKey,
            identityPublicKey: kp1.publicKey,
            sharedSecret: Data(count: 32)
        )
        contactsProvider.contacts = [contact1]

        viewModel.loadContacts()
        XCTAssertEqual(viewModel.contacts.count, 1)

        // Simulate switching to a different persona
        let persona2Id = "gaming"
        let kp2 = IDAPCrypto.generateEphemeralX25519()
        let contact2 = Contact(
            id: "c2",
            personaId: persona2Id,
            publicKey: kp2.publicKey,
            identityPublicKey: kp2.publicKey,
            sharedSecret: Data(count: 32)
        )
        contactsProvider.contacts.append(contact2)

        // persona1 contacts should not include persona2's contacts
        let filteredContacts = contactsProvider.listContacts(persona: persona1)
        XCTAssertEqual(filteredContacts.count, 1)
        XCTAssertFalse(filteredContacts.contains { $0.id == "c2" })
    }
}
