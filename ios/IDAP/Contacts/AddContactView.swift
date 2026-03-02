import SwiftUI
import CoreImage.CIFilterBuiltins

struct AddContactView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var viewModel: ContactsViewModel
    @State private var selectedTab: Tab = .connect
    @State private var codeCopied: Bool = false
    @State private var selectedProxy: URL?

    enum Tab { case connect, share }

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Picker("", selection: $selectedTab) {
                    Text("Connect").tag(Tab.connect)
                    Text("Share").tag(Tab.share)
                }
                .pickerStyle(.segmented)
                .padding(.horizontal)

                if !viewModel.availableProxies.isEmpty {
                    Picker("Proxy", selection: $selectedProxy) {
                        ForEach(viewModel.availableProxies, id: \.self) { proxy in
                            Text(proxy.host ?? proxy.absoluteString)
                                .tag(Optional(proxy))
                        }
                    }
                    .pickerStyle(.menu)
                    .padding(.horizontal)
                }

                switch selectedTab {
                case .share:
                    shareContent
                case .connect:
                    connectContent
                }

                Spacer()
            }
            .padding(.top)
            .navigationTitle("Add Contact")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear {
                selectedProxy = viewModel.defaultProxy
            }
            .task {
                if selectedTab == .share && viewModel.activeAccessCode == nil {
                    await viewModel.generateAccessCode(proxyURL: selectedProxy)
                }
            }
        }
    }

    @ViewBuilder
    private var shareContent: some View {
        if viewModel.isLoading && viewModel.activeAccessCode == nil {
            ProgressView("Generating code...")
        } else if let code = viewModel.activeAccessCode {
            VStack(spacing: 20) {
                Image(systemName: "person.badge.plus")
                    .font(.system(size: 48))
                    .foregroundStyle(.blue)

                Text("Your contact code")
                    .font(.headline)
                    .foregroundStyle(.secondary)

                HStack(spacing: 12) {
                    Text(code.code)
                        .font(.system(size: 48, weight: .bold, design: .monospaced))
                        .tracking(4)

                    Button {
                        UIPasteboard.general.string = code.code
                        codeCopied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { codeCopied = false }
                    } label: {
                        Image(systemName: codeCopied ? "checkmark" : "doc.on.doc")
                            .font(.title3)
                            .foregroundStyle(codeCopied ? .green : .blue)
                    }
                }

                if let url = viewModel.connectDeepLink(proxyURL: selectedProxy) {
                    ShareLink(item: url) {
                        Label("Share Link", systemImage: "square.and.arrow.up")
                            .font(.subheadline.weight(.medium))
                    }
                    .buttonStyle(.bordered)
                }

                Text("Share this code with someone to connect.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                if let url = viewModel.connectDeepLink(proxyURL: selectedProxy) {
                    QRCodeView(url: url)
                        .frame(width: 200, height: 200)
                }

                TimerRingView(seconds: viewModel.secondsRemaining, total: 300)
                    .frame(width: 64, height: 64)

                Button("Generate New Code") {
                    Task { await viewModel.generateAccessCode(proxyURL: selectedProxy) }
                }
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        } else {
            VStack(spacing: 16) {
                Text("Code expired")
                    .font(.headline)
                    .foregroundStyle(.secondary)
                Button("Generate New Code") {
                    Task { await viewModel.generateAccessCode(proxyURL: selectedProxy) }
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    @ViewBuilder
    private var connectContent: some View {
        VStack(spacing: 20) {
            Image(systemName: "link")
                .font(.system(size: 48))
                .foregroundStyle(.blue)

            Text("Enter a code or paste a link")
                .font(.headline)
                .foregroundStyle(.secondary)

            TextField("Code or idap:// link", text: $viewModel.codeEntryText)
                .font(.system(size: 20, weight: .medium, design: .monospaced))
                .multilineTextAlignment(.center)
                .textFieldStyle(.roundedBorder)
                .padding(.horizontal, 24)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

            Button {
                Task { await handleConnectInput() }
            } label: {
                Text("Connect")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .frame(height: 50)
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.codeEntryText.trimmingCharacters(in: .whitespaces).isEmpty)
            .padding(.horizontal)

            if viewModel.isLoading {
                ProgressView("Connecting...")
            }

            if let error = viewModel.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    private func handleConnectInput() async {
        let input = viewModel.codeEntryText.trimmingCharacters(in: .whitespaces)
        guard !input.isEmpty else { return }

        // Auto-detect: URL (idap:// or https://) vs plain code
        if input.hasPrefix("idap://") || input.hasPrefix("https://") {
            if let url = URL(string: input) {
                await viewModel.handleDeepLink(url)
            }
        } else {
            await viewModel.handleIncomingCode(input, proxyURL: selectedProxy)
        }
    }
}

private struct QRCodeView: View {
    let url: URL
    private let context = CIContext()
    private let filter = CIFilter.qrCodeGenerator()

    var body: some View {
        Image(uiImage: generateQRCode(from: url.absoluteString))
            .interpolation(.none)
            .resizable()
            .scaledToFit()
    }

    private func generateQRCode(from string: String) -> UIImage {
        filter.message = Data(string.utf8)
        if let output = filter.outputImage,
           let cgImage = context.createCGImage(output, from: output.extent) {
            return UIImage(cgImage: cgImage)
        }
        return UIImage(systemName: "qrcode") ?? UIImage()
    }
}
