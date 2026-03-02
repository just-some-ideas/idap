import SwiftUI

struct WelcomeView: View {
    let onGetStarted: () -> Void

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "key.fill")
                .font(.system(size: 80))
                .foregroundStyle(.blue)

            VStack(spacing: 12) {
                Text("IDAP")
                    .font(.largeTitle.bold())

                Text("Your identity, your keys.\nNo passwords. No accounts. Just you.")
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
            }

            VStack(alignment: .leading, spacing: 16) {
                FeatureRow(icon: "lock.fill", title: "Cryptographic identity", description: "Your keys are derived from a seed only you control.")
                FeatureRow(icon: "bell.fill", title: "One-tap login", description: "Approve logins with a number match and Face ID.")
                FeatureRow(icon: "person.2.fill", title: "Multiple personas", description: "Keep your real identity separate from others.")
            }
            .padding(.horizontal)

            Spacer()

            Button("Get Started") { onGetStarted() }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .padding(.horizontal)
        }
        .padding()
    }
}

private struct FeatureRow: View {
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(.blue)
                .frame(width: 32)

            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(description).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
