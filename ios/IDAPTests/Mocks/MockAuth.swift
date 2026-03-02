import Foundation
import IDAPAuth
import IDAPIdentity
@testable import IDAP

final class MockAuth: AuthProviding {
    var denyCalledWith: AuthRequest?
    var approveCalledWith: AuthRequest?

    func approveAuthRequest(_ request: AuthRequest, persona: Persona, seed: Data) -> SignedAssertion {
        approveCalledWith = request
        return SignedAssertion(jwt: "mock.jwt.token", requestId: request.requestId)
    }

    func denyAuthRequest(_ request: AuthRequest) {
        denyCalledWith = request
    }
}
