import SwiftUI
import IDAPContacts

struct ContactDetailView: View {
    let contact: Contact
    @EnvironmentObject var session: IDAPSession

    var body: some View {
        List {
            Section("Identity") {
                LabeledContent("Public Key", value: String(contact.publicKey.base64EncodedString().prefix(16)) + "...")
                LabeledContent("Shard", value: contact.holdsShardId != nil ? "Holds a recovery shard" : "No shard")
            }

            Section("Shared Info") {
                if let name = contact.displayName {
                    LabeledContent("Name", value: name)
                }
                if let email = contact.email {
                    LabeledContent("Email", value: email)
                }
                if let phone = contact.phone {
                    LabeledContent("Phone", value: phone)
                }
                if contact.displayName == nil && contact.email == nil && contact.phone == nil {
                    Text("No shared fields yet.")
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Button(role: .destructive) {
                    session.contacts.removeContact(contact)
                } label: {
                    Label("Remove Contact", systemImage: "trash")
                }
            }
        }
        .navigationTitle(contact.displayName ?? String(contact.publicKey.base64EncodedString().prefix(8)) + "...")
    }
}
