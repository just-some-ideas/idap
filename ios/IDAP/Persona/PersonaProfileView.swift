import SwiftUI

struct PersonaProfileView: View {
    @ObservedObject var viewModel: PersonaDetailViewModel

    var body: some View {
        Form {
            Section("Display Name") {
                TextField("Display Name", text: $viewModel.displayName)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.words)
            }

            Section("Bio") {
                TextField("Bio (optional)", text: $viewModel.bio)
                    .autocorrectionDisabled()
            }

            if viewModel.profileDirty {
                Section {
                    Button("Save Profile") {
                        viewModel.saveProfile()
                    }
                }
            }
        }
        .navigationTitle("Profile")
    }
}
