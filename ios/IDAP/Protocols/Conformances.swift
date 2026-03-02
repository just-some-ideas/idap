/// Protocol conformances for the real IDAP package types.
/// This allows ViewModels to depend on protocols while the app injects real instances.

import Foundation
import IDAPIdentity
import IDAPAuth
import IDAPContacts
import IDAPRecovery

extension IDAPIdentity: @retroactive IdentityStoring {}
extension IDAPAuth: @retroactive AuthProviding {}
extension IDAPContacts: @retroactive ContactsProviding {}
extension IDAPRecovery: @retroactive RecoveryProviding {}
