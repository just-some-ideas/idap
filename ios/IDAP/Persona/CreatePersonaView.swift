import SwiftUI
import IDAPIdentity

struct CreatePersonaView: View {
    @Environment(\.dismiss) private var dismiss
    let isInitialPersona: Bool
    var onCreated: ((Persona) -> Void)?

    @StateObject private var viewModel: PersonaCreationViewModel

    init(session: IDAPSession, isInitialPersona: Bool, onCreated: ((Persona) -> Void)? = nil) {
        self.isInitialPersona = isInitialPersona
        self.onCreated = onCreated
        _viewModel = StateObject(wrappedValue: PersonaCreationViewModel(
            identity: session.identity,
            session: session
        ))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Display Name (Optional)") {
                    TextField("e.g. Alice", text: $viewModel.displayName)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.words)
                }

                if let error = viewModel.errorMessage {
                    Section {
                        Text(error).foregroundStyle(.red).font(.caption)
                    }
                }
            }
            .navigationTitle(isInitialPersona ? "Create Your Identity" : "Add Persona")
            .toolbar {
                if !isInitialPersona {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Create") {
                        Task {
                            await viewModel.createPersona()
                            if viewModel.errorMessage == nil {
                                if let persona = viewModel.createdPersona, let onCreated {
                                    dismiss()
                                    onCreated(persona)
                                } else {
                                    dismiss()
                                }
                            }
                        }
                    }
                    .disabled(!viewModel.isFormValid || viewModel.isCreating)
                    .overlay {
                        if viewModel.isCreating { ProgressView() }
                    }
                }
            }
        }
    }
}
