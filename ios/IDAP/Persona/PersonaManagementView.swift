import SwiftUI
import IDAPIdentity

struct PersonaManagementView: View {
    @ObservedObject var session: IDAPSession
    @State private var showingCreatePersona = false
    @State private var createdPersonaId: String?
    @State private var showCreatedDetail = false

    var body: some View {
        List {
            Section {
                ForEach(session.personas, id: \.id) { persona in
                    NavigationLink {
                        PersonaDetailView(persona: persona, session: session)
                    } label: {
                        PersonaRow(persona: persona, isActive: persona.id == session.activePersona?.id)
                    }
                }
            }

            Section {
                Button {
                    showingCreatePersona = true
                } label: {
                    Label("Create Persona", systemImage: "plus")
                }
            }
        }
        .navigationTitle("Personas")
        .navigationDestination(isPresented: $showCreatedDetail) {
            if let id = createdPersonaId,
               let persona = session.personas.first(where: { $0.id == id }) {
                PersonaDetailView(persona: persona, session: session)
            }
        }
        .sheet(isPresented: $showingCreatePersona) {
            CreatePersonaView(session: session, isInitialPersona: false) { persona in
                createdPersonaId = persona.id
                showCreatedDetail = true
            }
        }
    }
}

private struct PersonaRow: View {
    let persona: Persona
    let isActive: Bool

    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(isActive ? Color.blue : Color.gray.opacity(0.3))
                .frame(width: 36, height: 36)
                .overlay {
                    Text(initial)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(isActive ? .white : .secondary)
                }

            VStack(alignment: .leading, spacing: 2) {
                Text(persona.displayLabel)
                    .font(.body)
                if persona.proxies.isEmpty {
                    Text("No proxies")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("\(persona.proxies.count) proxy(s)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private var initial: String {
        guard let name = persona.publicProfile?.displayName, !name.isEmpty else {
            return String(persona.id.prefix(1)).uppercased()
        }
        return String(name.prefix(1)).uppercased()
    }
}
