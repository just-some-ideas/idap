import SwiftUI
import IDAPCrypto
import IDAPIdentity

struct ProxyRegistrationSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var urlString: String = "http://localhost:8080"
    @State private var isRegistering = false
    @State private var errorMessage: String?
    @State private var successMessage: String?

    let session: IDAPSession
    let persona: Persona
    let onRegistered: () -> Void

    var body: some View {
        NavigationStack {
            Form {
                Section("Proxy URL") {
                    TextField("http://localhost:8080", text: $urlString)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                if let error = errorMessage {
                    Section {
                        Text(error).foregroundStyle(.red).font(.caption)
                    }
                }
                if let success = successMessage {
                    Section {
                        Text(success).foregroundStyle(.green).font(.caption)
                    }
                }
            }
            .navigationTitle("Register Proxy")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Register") {
                        Task { await register() }
                    }
                    .disabled(URL(string: urlString) == nil || isRegistering)
                    .overlay {
                        if isRegistering { ProgressView() }
                    }
                }
            }
        }
    }

    private func register() async {
        guard let proxyURL = URL(string: urlString),
              let seed = session.seed else { return }

        isRegistering = true
        errorMessage = nil
        successMessage = nil

        let personaKP = session.identity.getPersonaKey(persona: persona, seed: seed)
        let pubkeyB64url = stdToB64url(personaKP.publicKey.base64EncodedString())
        let regURL = proxyURL.appendingPathComponent("keys/\(pubkeyB64url)")
        var request = URLRequest(url: regURL)
        request.httpMethod = "PUT"

        // Build V2 typed key bundle
        let signingKey = TypedKey(kty: .ed25519, rawKey: personaKP.publicKey)
        let ikSeed = IDAPCrypto.hkdf(secret: seed,
                                      salt: Data("idap-contact-identity".utf8),
                                      info: Data(persona.id.utf8),
                                      length: 32)
        let contactIdentityKP = IDAPCrypto.generateEphemeralX25519FromSeed(ikSeed)
        let agreementKey = TypedKey(kty: .x25519, rawKey: contactIdentityKP.publicKey)

        let bundle: [String: Any] = [
            "signing_key": ["kty": signingKey.kty.rawValue, "key": signingKey.key],
            "agreement_key": ["kty": agreementKey.kty.rawValue, "key": agreementKey.key]
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: bundle)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            let httpResponse = response as? HTTPURLResponse
            if let status = httpResponse?.statusCode, status >= 200 && status < 300 {
                session.identity.registerProxy(proxyURL, for: persona)
                onRegistered()
                successMessage = "Registered successfully"
                try? await Task.sleep(nanoseconds: 500_000_000)
                dismiss()
            } else {
                errorMessage = "Registration failed (HTTP \(httpResponse?.statusCode ?? 0))"
            }
        } catch {
            errorMessage = "Network error: \(error.localizedDescription)"
        }

        isRegistering = false
    }
}
