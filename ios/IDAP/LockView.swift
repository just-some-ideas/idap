import SwiftUI
import LocalAuthentication
import IDAPCrypto

struct LockView: View {
    @EnvironmentObject var session: IDAPSession
    @State private var errorMessage: String?
    @State private var isUnlocking: Bool = false

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "lock.circle.fill")
                .font(.system(size: 64))
                .foregroundStyle(.primary)

            Text("IDAP")
                .font(.largeTitle.bold())

            if let error = errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.caption)
            }

            #if !targetEnvironment(simulator)
            Button {
                Task { await unlockWithBiometrics() }
            } label: {
                if isUnlocking {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                } else {
                    Label("Unlock with Face ID", systemImage: "faceid")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .frame(maxWidth: 280)
            .disabled(isUnlocking)
            #endif

            Spacer()
        }
        .padding()
        .onAppear {
            #if targetEnvironment(simulator)
            // Simulator: load seed directly (stored unencrypted)
            if let seed = try? session.keychain.loadSeedCiphertext() {
                session.unlock(seed: seed)
            }
            #else
            Task { await unlockWithBiometrics() }
            #endif
        }
    }

    private func unlockWithBiometrics() async {
        isUnlocking = true
        errorMessage = nil
        defer { isUnlocking = false }

        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            errorMessage = "Biometrics not available."
            return
        }
        do {
            let granted = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Unlock IDAP"
            )
            guard granted else { return }
            if let ciphertext = try? session.keychain.loadSeedCiphertext(),
               let seed = IDAPCrypto.enclaveDecrypt(label: "idap.master", ciphertext: ciphertext) {
                session.unlock(seed: seed)
            } else {
                errorMessage = "Failed to decrypt seed."
            }
        } catch {
            errorMessage = "Biometrics dismissed. Tap to retry."
        }
    }
}
