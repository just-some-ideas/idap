import SwiftUI

struct RecoveryPhraseView: View {
    @ObservedObject var viewModel: OnboardingViewModel
    @State private var showingVerification: Bool = false

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                Text("Recovery Phrase")
                    .font(.largeTitle.bold())

                Text("Write down these 24 words and store them somewhere safe. This is the only other way to recover your identity if you lose this device.")
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)

                if !showingVerification {
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                        ForEach(Array(viewModel.mnemonicWords.enumerated()), id: \.offset) { index, word in
                            HStack(spacing: 4) {
                                Text("\(index + 1).")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .frame(width: 24, alignment: .trailing)
                                Text(word)
                                    .font(.system(.body, design: .monospaced))
                            }
                            .padding(.vertical, 4)
                        }
                    }
                    .padding(.horizontal)
                }

                if viewModel.verificationFailed {
                    Text("Incorrect. Please check your words and try again.")
                        .foregroundStyle(.red)
                        .font(.caption)
                }

                if showingVerification {
                    VerificationView(viewModel: viewModel) {
                        viewModel.resetVerification()
                        showingVerification = false
                    }
                } else {
                    VStack(spacing: 12) {
                        Button("I've Written It Down") {
                            viewModel.resetVerification()
                            showingVerification = true
                        }
                        .buttonStyle(.borderedProminent)
                        .frame(maxWidth: .infinity)

                        Button("Skip for Now") {
                            viewModel.skipRecoveryPhrase()
                        }
                        .foregroundStyle(.secondary)
                    }
                }
            }
            .padding()
        }
    }
}

private struct VerificationView: View {
    @ObservedObject var viewModel: OnboardingViewModel
    let onBack: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Text("Verify Recovery Phrase")
                .font(.headline)

            Text("Enter the following words to confirm you've written them down:")
                .font(.callout)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            ForEach(viewModel.verificationIndices, id: \.self) { idx in
                HStack {
                    Text("Word \(idx + 1):")
                        .frame(width: 80, alignment: .leading)
                    TextField("", text: Binding(
                        get: { viewModel.verificationAnswers[idx] ?? "" },
                        set: { viewModel.verificationAnswers[idx] = $0 }
                    ))
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                }
            }

            HStack(spacing: 16) {
                Button("Back") { onBack() }
                    .foregroundStyle(.secondary)

                Button("Confirm") {
                    viewModel.confirmRecoveryPhrase()
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.verificationIndices.contains(where: {
                    viewModel.verificationAnswers[$0]?.isEmpty != false
                }))
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
