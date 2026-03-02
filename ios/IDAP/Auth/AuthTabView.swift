import SwiftUI

struct AuthTabView: View {
    @StateObject private var viewModel: LoginCodeViewModel
    @ObservedObject private var session: IDAPSession
    @State private var selectedProxy: URL?

    init(session: IDAPSession) {
        self.session = session
        _viewModel = StateObject(wrappedValue: LoginCodeViewModel(session: session))
    }

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            if let proxies = session.activePersona?.proxies, !proxies.isEmpty {
                Picker("Proxy", selection: $selectedProxy) {
                    ForEach(proxies, id: \.self) { proxy in
                        Text(proxy.host ?? proxy.absoluteString)
                            .tag(Optional(proxy))
                    }
                }
                .pickerStyle(.menu)
                .padding(.horizontal)
            } else {
                Label("No proxies registered", systemImage: "exclamationmark.triangle")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

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
        .onAppear {
            selectedProxy = session.activePersona?.primaryProxy
        }
        .onChange(of: session.activePersona?.id) { _ in
            selectedProxy = session.activePersona?.primaryProxy
            viewModel.state = .idle
        }
        .task {
            await viewModel.requestCode(proxyURL: selectedProxy)
        }
    }

    private var idleContent: some View {
        VStack(spacing: 16) {
            Text("Code expired")
                .font(.headline)
                .foregroundStyle(.secondary)
            Button("Generate New Code") {
                Task { await viewModel.requestCode(proxyURL: selectedProxy) }
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
                Task { await viewModel.requestCode(proxyURL: selectedProxy) }
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
                Task { await viewModel.requestCode(proxyURL: selectedProxy) }
            }
            .buttonStyle(.borderedProminent)
        }
    }
}
