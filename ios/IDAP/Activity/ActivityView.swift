import SwiftUI

struct ActivityView: View {
    @ObservedObject private var session: IDAPSession
    @StateObject private var viewModel: ActivityViewModel

    init(session: IDAPSession) {
        self.session = session
        _viewModel = StateObject(wrappedValue: ActivityViewModel(
            store: session.activityStore,
            session: session
        ))
    }

    var body: some View {
        Group {
            if viewModel.events.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "list.bullet.rectangle")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("No activity yet")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                    Text("Login requests will appear here.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            } else {
                List(viewModel.events) { event in
                    NavigationLink {
                        ActivityDetailView(event: event)
                    } label: {
                        ActivityRow(event: event)
                    }
                }
            }
        }
        .navigationTitle("Activity")
        .onAppear { viewModel.loadEvents() }
        .onChange(of: session.activePersona?.id) { _ in viewModel.loadEvents() }
    }
}

private struct ActivityRow: View {
    let event: ActivityEvent

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: event.approved ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(event.approved ? .green : .red)
                .font(.title2)

            VStack(alignment: .leading, spacing: 4) {
                Text(event.serviceName)
                    .font(.headline)
                Text(event.timestamp, style: .relative)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Text(event.approved ? "Approved" : "Denied")
                .font(.caption)
                .foregroundStyle(event.approved ? .green : .red)
        }
        .padding(.vertical, 4)
    }
}

private struct ActivityDetailView: View {
    let event: ActivityEvent

    var body: some View {
        List {
            Section("Request") {
                LabeledContent("Service", value: event.serviceName)
                LabeledContent("Persona", value: event.personaLabel)
                LabeledContent("Status", value: event.approved ? "Approved" : "Denied")
                LabeledContent("Time", value: event.timestamp.formatted())
            }

            if !event.scopes.isEmpty {
                Section("Scopes Requested") {
                    ForEach(event.scopes, id: \.self) { scope in
                        Text(scope)
                    }
                }
            }
        }
        .navigationTitle(event.serviceName)
    }
}
