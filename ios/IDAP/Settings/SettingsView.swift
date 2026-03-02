import SwiftUI

struct SettingsView: View {
    @StateObject private var viewModel: SettingsViewModel

    init(session: IDAPSession) {
        _viewModel = StateObject(wrappedValue: SettingsViewModel(
            crypto: IDAPCryptoService(),
            keychain: session.keychain,
            session: session
        ))
    }

    var body: some View {
        List {
            // Recovery phrase section
            Section("Recovery") {
                Button {
                    Task { await viewModel.revealRecoveryPhrase() }
                } label: {
                    Label("View Recovery Phrase", systemImage: "key.fill")
                }
                .sheet(isPresented: $viewModel.showingRecoveryPhrase) {
                    RecoveryPhraseDisplayView(words: viewModel.mnemonicWords)
                }

                LabeledContent("Recovery Contacts", value: viewModel.recoveryMap)
            }

            // About
            Section("About") {
                LabeledContent("Version", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
                Link("Open Source", destination: URL(string: "https://github.com/anthropics/idap")!)
            }
        }
        .navigationTitle("Settings")
        .alert("Error", isPresented: Binding(
            get: { viewModel.errorMessage != nil },
            set: { if !$0 { viewModel.errorMessage = nil } }
        )) {
            Button("OK") {}
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }
}

private struct RecoveryPhraseDisplayView: View {
    @Environment(\.dismiss) private var dismiss
    let words: [String]

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    ForEach(Array(words.enumerated()), id: \.offset) { index, word in
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
                .padding()
            }
            .navigationTitle("Recovery Phrase")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}
