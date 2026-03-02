import SwiftUI

struct PersonaDangerZoneView: View {
    @ObservedObject var viewModel: PersonaDetailViewModel
    @State private var showingDeleteConfirm = false

    var body: some View {
        List {
            Section {
                Button(role: .destructive) {
                    showingDeleteConfirm = true
                } label: {
                    Label("Delete Persona", systemImage: "trash")
                        .foregroundStyle(.red)
                }
            } footer: {
                Text("This will permanently remove this persona from your device.")
            }
        }
        .navigationTitle("Danger Zone")
        .alert("Delete Persona", isPresented: $showingDeleteConfirm) {
            Button("Delete", role: .destructive) {
                viewModel.deletePersona()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will permanently remove this persona and all its data.")
        }
    }
}
