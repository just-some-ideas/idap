import SwiftUI
import IDAPIdentity

struct PersonaDetailView: View {
    @StateObject private var viewModel: PersonaDetailViewModel
    @Environment(\.dismiss) private var dismiss

    init(persona: Persona, session: IDAPSession) {
        _viewModel = StateObject(wrappedValue: PersonaDetailViewModel(
            persona: persona,
            session: session
        ))
    }

    var body: some View {
        List {
            NavigationLink {
                PersonaProfileView(viewModel: viewModel)
            } label: {
                Label("Profile", systemImage: "person.fill")
            }

            NavigationLink {
                PersonaProxiesView(viewModel: viewModel)
            } label: {
                HStack {
                    Label("Proxies", systemImage: "network")
                    Spacer()
                    Text("\(viewModel.proxies.count)")
                        .foregroundStyle(.secondary)
                }
            }

            NavigationLink {
                PersonaIdentityView(viewModel: viewModel)
            } label: {
                Label("Identity", systemImage: "key.fill")
            }

            NavigationLink {
                PersonaDangerZoneView(viewModel: viewModel)
            } label: {
                Label("Danger Zone", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }
        }
        .navigationTitle(viewModel.persona.displayLabel)
        .onChange(of: viewModel.isDeleted) { deleted in
            if deleted { dismiss() }
        }
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
