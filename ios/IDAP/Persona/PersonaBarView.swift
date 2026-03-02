import SwiftUI
import IDAPIdentity

struct PersonaBarView: View {
    let persona: Persona?
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 8) {
                Circle()
                    .fill(Color.blue)
                    .frame(width: 28, height: 28)
                    .overlay {
                        Text(initial)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(.white)
                    }

                Text(persona?.displayLabel ?? "No Persona")
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)

                Image(systemName: "chevron.down")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
        }
        .buttonStyle(.plain)
    }

    private var initial: String {
        guard let name = persona?.publicProfile?.displayName, !name.isEmpty else {
            return "?"
        }
        return String(name.prefix(1)).uppercased()
    }
}
