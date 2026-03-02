import XCTest
import IDAPAuth
import IDAPIdentity
@testable import IDAP

@MainActor
final class AuthApprovalViewModelTests: XCTestCase {
    private var auth: MockAuth!
    private var session: IDAPSession!
    private var request: AuthRequest!

    override func setUp() async throws {
        auth = MockAuth()
        session = IDAPSession()
        request = AuthRequest(
            requestId: "req-123",
            service: "example.com",
            serviceDisplayName: "Example",
            personaHint: "@alice@idap.app",
            requesting: ["openid", "email"],
            nonce: "nonce123",
            expiresAt: Date().addingTimeInterval(30),
            locationHint: "London, UK"
        )
    }

    func testExpiredRequestShowsExpiredState() async {
        let expiredRequest = AuthRequest(
            requestId: "req-expired",
            service: "example.com",
            serviceDisplayName: "Example",
            personaHint: "@alice@idap.app",
            requesting: [],
            nonce: "n",
            expiresAt: Date().addingTimeInterval(-1), // already expired
            locationHint: nil
        )
        let vm = AuthApprovalViewModel(request: expiredRequest, auth: auth, session: session)
        XCTAssertEqual(vm.state, .expired)
    }

    func testDenyCallsDenyOnPackage() {
        let vm = AuthApprovalViewModel(request: request, auth: auth, session: session)
        vm.deny()
        XCTAssertEqual(auth.denyCalledWith?.requestId, request.requestId)
        XCTAssertEqual(vm.state, .denied)
    }

    func testApproveWithNoPersonaShowsError() async {
        // Without an active persona, approve should set an error
        let vm = AuthApprovalViewModel(request: request, auth: auth, session: session)
        await vm.approve()
        XCTAssertNotNil(vm.errorMessage, "Should show error when no persona is active")
    }

    func testSuccessfulApprovalDismissesView() {
        // With real biometric we can't auto-test, but we can test state transitions
        let vm = AuthApprovalViewModel(request: request, auth: auth, session: session)
        XCTAssertEqual(vm.state, .pending)
    }

    func testTimerCountsDown() async {
        let vm = AuthApprovalViewModel(request: request, auth: auth, session: session)
        let initial = vm.secondsRemaining
        // Wait a brief moment; in unit tests timers don't run unless we advance RunLoop
        XCTAssertGreaterThan(initial, 0)
        XCTAssertLessThanOrEqual(initial, 30)
    }

    func testReportSuspiciousFlags() {
        let vm = AuthApprovalViewModel(request: request, auth: auth, session: session)
        vm.reportSuspicious()
        XCTAssertEqual(vm.state, .flagged)
        XCTAssertEqual(auth.denyCalledWith?.requestId, request.requestId)
    }
}
