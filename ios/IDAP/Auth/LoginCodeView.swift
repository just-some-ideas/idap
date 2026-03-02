import SwiftUI

struct LoginCodeView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var viewModel: LoginCodeViewModel

    init(session: IDAPSession) {
        _viewModel = StateObject(wrappedValue: LoginCodeViewModel(session: session))
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Spacer()

                switch viewModel.state {
                case .idle:
                    idleContent
                case .loading:
                    ProgressView("Generating code...")
                case .showing(let code):
                    codeContent(code)
                case .error(let message):
                    errorContent(message)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("Log In")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                await viewModel.requestCode()
            }
        }
    }

    private var idleContent: some View {
        VStack(spacing: 16) {
            Text("Code expired")
                .font(.headline)
                .foregroundStyle(.secondary)
            Button("Generate New Code") {
                Task { await viewModel.requestCode() }
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private func codeContent(_ code: String) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "key.fill")
                .font(.system(size: 48))
                .foregroundStyle(.blue)

            Text("Your login code")
                .font(.headline)
                .foregroundStyle(.secondary)

            Text(code)
                .font(.system(size: 48, weight: .bold, design: .monospaced))
                .tracking(4)

            Text("Enter this code on the website or app you're signing into.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            TimerRingView(seconds: viewModel.secondsRemaining, total: 300)
                .frame(width: 64, height: 64)

            Button("Generate New Code") {
                Task { await viewModel.requestCode() }
            }
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    private func errorContent(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(.orange)

            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Button("Try Again") {
                Task { await viewModel.requestCode() }
            }
            .buttonStyle(.borderedProminent)
        }
    }
}
