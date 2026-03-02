import SwiftUI
import IDAPContacts

struct ContactsView: View {
    @StateObject private var viewModel: ContactsViewModel
    @ObservedObject private var session: IDAPSession
    var onAddContact: (() -> Void)?

    init(session: IDAPSession, onAddContact: (() -> Void)? = nil) {
        self.session = session
        self.onAddContact = onAddContact
        _viewModel = StateObject(wrappedValue: ContactsViewModel(
            contactsProvider: session.contacts,
            session: session
        ))
    }

    var body: some View {
        Group {
            if viewModel.contacts.isEmpty {
                EmptyContactsView(onAdd: { onAddContact?() })
            } else {
                List {
                    ForEach(viewModel.contacts, id: \.id) { contact in
                        NavigationLink {
                            ContactDetailView(contact: contact)
                        } label: {
                            ContactRow(contact: contact)
                        }
                    }
                    .onDelete { indices in
                        for i in indices {
                            viewModel.removeContact(viewModel.contacts[i])
                        }
                    }
                }
            }
        }
        .navigationTitle("Contacts")
        .onAppear { viewModel.loadContacts() }
        .onChange(of: session.activePersona?.id) { _ in viewModel.loadContacts() }
        .onChange(of: session.contactsVersion) { _ in viewModel.loadContacts() }
    }
}

// MARK: - Subviews

private struct EmptyContactsView: View {
    let onAdd: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "person.badge.plus")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("No contacts yet")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Share your access code to add contacts.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Add Contact") { onAdd() }
                .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}

private struct ContactRow: View {
    let contact: Contact

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(Color.teal.opacity(0.2))
                .frame(width: 40, height: 40)
                .overlay {
                    Text((contact.displayName ?? "?").prefix(1).uppercased())
                        .font(.headline)
                        .foregroundStyle(.teal)
                }

            VStack(alignment: .leading, spacing: 4) {
                Text(contact.displayName ?? String(contact.publicKey.base64EncodedString().prefix(8)) + "...")
                    .font(.headline)
                Text(String(contact.publicKey.base64EncodedString().prefix(12)) + "...")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
