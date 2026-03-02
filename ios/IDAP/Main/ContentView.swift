import SwiftUI
import IDAPIdentity

struct ContentView: View {
    @EnvironmentObject var session: IDAPSession
    @State private var selectedTab: Tab = .contacts
    @State private var showPersonaSwitcher = false
    @State private var showAddContact = false
    @State private var showCreatePersona = false
    @State private var managingPersonaId: String?
    @State private var preferredColumn: NavigationSplitViewColumn = .sidebar

    enum Tab {
        case contacts, activity, auth
    }

    var body: some View {
        NavigationSplitView(preferredCompactColumn: $preferredColumn) {
            sidebar
        } detail: {
            detail
                .toolbar {
                    ToolbarItem(placement: .principal) {
                        PersonaBarView(persona: session.activePersona, onTap: {
                            showPersonaSwitcher = true
                        })
                    }
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button { showAddContact = true } label: {
                            Image(systemName: "person.badge.plus")
                        }
                    }
                }
        }
        .sheet(isPresented: $showPersonaSwitcher) {
            PersonaSwitcherSheet()
                .environmentObject(session)
        }
        .sheet(isPresented: $showAddContact) {
            AddContactView(viewModel: ContactsViewModel(
                contactsProvider: session.contacts,
                session: session
            ))
        }
        .onAppear {
            if session.activePersona != nil {
                preferredColumn = .detail
            }
        }
        .onChange(of: session.pendingAuthRequest != nil) { hasPending in
            if hasPending {
                // Switch away from auth tab if needed
            }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List {
            Section("Personas") {
                ForEach(session.personas, id: \.id) { persona in
                    HStack(spacing: 12) {
                        Button {
                            session.setActivePersona(persona)
                            preferredColumn = .detail
                        } label: {
                            HStack(spacing: 12) {
                                Circle()
                                    .fill(persona.id == session.activePersona?.id ? Color.blue : Color.gray.opacity(0.3))
                                    .frame(width: 32, height: 32)
                                    .overlay {
                                        Text(personaInitial(persona))
                                            .font(.system(size: 13, weight: .semibold))
                                            .foregroundStyle(persona.id == session.activePersona?.id ? .white : .secondary)
                                    }
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(persona.displayLabel)
                                        .font(.body)
                                    if persona.id == session.activePersona?.id {
                                        Text("Active")
                                            .font(.caption)
                                            .foregroundStyle(.blue)
                                    }
                                }
                            }
                        }

                        Spacer()

                        Button {
                            managingPersonaId = persona.id
                        } label: {
                            Image(systemName: "gearshape")
                                .foregroundStyle(.secondary)
                        }
                    }
                    .buttonStyle(.borderless)
                }

                Button {
                    showCreatePersona = true
                } label: {
                    Label("New Persona", systemImage: "plus")
                }
            }

            Section {
                NavigationLink {
                    SettingsView(session: session)
                } label: {
                    Label("Settings", systemImage: "gearshape.fill")
                }
            }
        }
        .navigationTitle("IDAP")
        .navigationDestination(isPresented: Binding(
            get: { managingPersonaId != nil },
            set: { if !$0 { managingPersonaId = nil } }
        )) {
            if let id = managingPersonaId,
               let persona = session.personas.first(where: { $0.id == id }) {
                PersonaDetailView(persona: persona, session: session)
            }
        }
        .sheet(isPresented: $showCreatePersona) {
            CreatePersonaView(session: session, isInitialPersona: false) { persona in
                managingPersonaId = persona.id
            }
        }
    }

    // MARK: - Detail

    private var detail: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                ContactsView(session: session, onAddContact: { showAddContact = true })
            }
            .tabItem { Label("Contacts", systemImage: "person.2.fill") }
            .tag(Tab.contacts)

            NavigationStack {
                ActivityView(session: session)
            }
            .tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
            .tag(Tab.activity)

            NavigationStack {
                AuthTabView(session: session)
            }
            .tabItem { Label("Auth", systemImage: "key.fill") }
            .tag(Tab.auth)
        }
    }

    private func personaInitial(_ persona: Persona) -> String {
        guard let name = persona.publicProfile?.displayName, !name.isEmpty else {
            return String(persona.id.prefix(1)).uppercased()
        }
        return String(name.prefix(1)).uppercased()
    }
}
