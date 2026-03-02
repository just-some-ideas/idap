import SwiftUI

struct PersonaIdentityView: View {
    @ObservedObject var viewModel: PersonaDetailViewModel

    var body: some View {
        List {
            LabeledContent("Public Key", value: String(viewModel.persona.publicKey.base64EncodedString().prefix(16)) + "...")
            LabeledContent("Derivation Index", value: "\(viewModel.persona.derivationIndex)")
            LabeledContent("ID", value: viewModel.persona.id)
        }
        .navigationTitle("Identity")
    }
}
