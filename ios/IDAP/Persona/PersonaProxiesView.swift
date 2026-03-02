import SwiftUI

struct PersonaProxiesView: View {
    @ObservedObject var viewModel: PersonaDetailViewModel
    @State private var showingProxyRegistration = false

    var body: some View {
        List {
            if viewModel.proxies.isEmpty {
                Text("No proxies registered")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.proxies, id: \.absoluteString) { url in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(url.host ?? url.absoluteString)
                                .font(.body)
                            Text(url.absoluteString)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(role: .destructive) {
                            viewModel.removeProxy(url)
                        } label: {
                            Image(systemName: "trash")
                                .foregroundStyle(.red)
                        }
                    }
                }
            }

            Section {
                Button {
                    showingProxyRegistration = true
                } label: {
                    Label("Register with Proxy", systemImage: "plus")
                }
            }
        }
        .navigationTitle("Proxies")
        .sheet(isPresented: $showingProxyRegistration) {
            ProxyRegistrationSheet(session: viewModel.session, persona: viewModel.persona) {
                viewModel.refreshProxies()
            }
        }
    }
}
