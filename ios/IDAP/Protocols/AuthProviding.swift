import Foundation
import IDAPAuth
import IDAPIdentity

protocol AuthProviding {
    func approveAuthRequest(_ request: AuthRequest, persona: Persona, seed: Data) -> SignedAssertion
    func denyAuthRequest(_ request: AuthRequest)
}
