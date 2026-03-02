import XCTest
import IDAPIdentity
@testable import IDAP

@MainActor
final class PersonaViewModelTests: XCTestCase {
    private var identity: MockIdentity!
    private var session: IDAPSession!
    private var viewModel: PersonaCreationViewModel!

    override func setUp() async throws {
        identity = MockIdentity()
        session = IDAPSession()
        viewModel = PersonaCreationViewModel(identity: identity, session: session)
    }

    func testCreatePersonaCallsIdentity() async {
        let seed = Data(repeating: 0x42, count: 32)
        session.unlock(seed: seed)

        await viewModel.createPersona()

        XCTAssertTrue(identity.createPersonaCalled)
        let created = identity.personas.first
        XCTAssertNotNil(created)
        XCTAssertNotNil(created?.publicKey)
    }

    func testFormAlwaysValid() {
        XCTAssertTrue(viewModel.isFormValid)
    }

    func testDisplayNameIsOptional() {
        viewModel.displayName = ""
        XCTAssertTrue(viewModel.isFormValid, "Display name should be optional")
    }

    func testPersonasAppearIndependentInUI() {
        let personas = identity.listPersonas()
        for persona in personas {
            XCTAssertNil(persona.publicProfile?.bio?.contains("master"),
                "Persona bio should not reference master account")
        }
    }
}
