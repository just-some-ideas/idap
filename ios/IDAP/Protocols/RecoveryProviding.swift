import Foundation
import IDAPRecovery
import IDAPContacts

protocol RecoveryProviding {
    func generateRecoveryMap(seed: Data, contacts: [Contact]) -> RecoveryMap
    func fetchRecoveryMap() throws -> RecoveryMap?
    func saveRecoveryMap(_ map: RecoveryMap) throws
}
