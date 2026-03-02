import SwiftUI
import IDAPContacts

struct CapabilityRequestView: View {
    @Environment(\.dismiss) private var dismiss
    @StateObject private var viewModel: CapabilityRequestViewModel

    init(request: CapabilityRequest, session: IDAPSession) {
        _viewModel = StateObject(wrappedValue: CapabilityRequestViewModel(
            request: request, session: session))
    }

    var body: some View {
        Group {
            switch viewModel.state {
            case .pending, .approving:
                requestContent
            case .approved:
                resultView(icon: "checkmark.circle.fill", color: .green, message: "Contact Added")
            case .denied:
                resultView(icon: "xmark.circle.fill", color: .red, message: "Denied")
            }
        }
        .onChange(of: viewModel.state) { _, state in
            if state == .approved || state == .denied {
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { dismiss() }
            }
        }
    }

    private var requestContent: some View {
        ScrollView {
            VStack(spacing: 0) {
                HStack {
                    Spacer()
                    Button("Deny") { Task { await viewModel.deny() } }
                        .foregroundStyle(.red)
                        .padding()
                }

                VStack(spacing: 8) {
                    Image(systemName: "person.badge.plus")
                        .font(.system(size: 48))
                        .foregroundStyle(.blue)

                    Text("Contact Request")
                        .font(.title2.bold())

                    Text("Someone wants to connect with you")
                        .foregroundStyle(.secondary)
                }

                if let identity = viewModel.request.identity, !identity.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Identity:")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        ForEach(Array(identity.keys.sorted()), id: \.self) { key in
                            if let value = identity[key] {
                                LabeledContent(key.capitalized, value: value)
                                    .font(.callout)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal)
                    .padding(.top, 16)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Requesting access to:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(viewModel.request.requestedAccess.categories, id: \.self) { cat in
                        Label(cat.capitalized, systemImage: "folder")
                            .font(.callout)
                    }
                    ForEach(viewModel.request.requestedAccess.messageTypes, id: \.self) { type in
                        Label(type.replacingOccurrences(of: "_", with: " ").capitalized,
                              systemImage: "envelope")
                            .font(.callout)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
                .background(Color(.systemGray6))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .padding(.horizontal)
                .padding(.top, 16)

                Button {
                    Task { await viewModel.approve() }
                } label: {
                    Text("Approve")
                        .font(.title2.bold())
                        .frame(maxWidth: .infinity)
                        .frame(height: 56)
                        .background(Color.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                }
                .disabled(viewModel.state == .approving)
                .padding(.horizontal)
                .padding(.top, 24)

                if viewModel.state == .approving {
                    ProgressView("Processing...").padding()
                }

                if let error = viewModel.errorMessage {
                    Text(error).font(.caption).foregroundStyle(.red).padding(.horizontal)
                }
            }
            .padding(.bottom, 32)
        }
    }

    private func resultView(icon: String, color: Color, message: String) -> some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: icon).font(.system(size: 80)).foregroundStyle(color)
            Text(message).font(.largeTitle.bold())
            Spacer()
        }
    }
}
