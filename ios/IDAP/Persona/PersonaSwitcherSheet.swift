import SwiftUI
import IDAPIdentity

struct PersonaSwitcherSheet: View {
    @EnvironmentObject var session: IDAPSession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            ForEach(session.personas, id: \.id) { persona in
                Button {
                    session.setActivePersona(persona)
                    dismiss()
                } label: {
                    HStack(spacing: 12) {
                        Circle()
                            .fill(persona.id == session.activePersona?.id ? Color.blue : Color.gray.opacity(0.3))
                            .frame(width: 36, height: 36)
                            .overlay {
                                Text(initial(for: persona))
                                    .font(.system(size: 14, weight: .semibold))
                                    .foregroundStyle(persona.id == session.activePersona?.id ? .white : .secondary)
                            }

                        VStack(alignment: .leading, spacing: 2) {
                            Text(persona.displayLabel)
                                .font(.body)
                                .foregroundStyle(.primary)
                            if let proxy = persona.primaryProxy {
                                Text(proxy.host ?? proxy.absoluteString)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        Spacer()

                        if persona.id == session.activePersona?.id {
                            Image(systemName: "checkmark")
                                .foregroundStyle(.blue)
                                .fontWeight(.semibold)
                        }
                    }
                }
            }
        }
        .safeAreaInset(edge: .top) {
            HStack {
                Text("Switch Persona")
                    .font(.headline)
                Spacer()
                Button("Done") { dismiss() }
            }
            .padding()
        }
        .presentationDetents([.medium])
    }

    private func initial(for persona: Persona) -> String {
        guard let name = persona.publicProfile?.displayName, !name.isEmpty else {
            return String(persona.id.prefix(1)).uppercased()
        }
        return String(name.prefix(1)).uppercased()
    }
}
