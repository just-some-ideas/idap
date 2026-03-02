import SwiftUI
import IDAPAuth
import IDAPIdentity

struct AuthApprovalView: View {
    @Environment(\.dismiss) private var dismiss

    let request: AuthRequest
    @StateObject private var viewModel: AuthApprovalViewModel

    init(request: AuthRequest, session: IDAPSession) {
        self.request = request
        _viewModel = StateObject(wrappedValue: AuthApprovalViewModel(
            request: request,
            auth: session.auth,
            session: session
        ))
    }

    var body: some View {
        Group {
            switch viewModel.state {
            case .pending, .authenticating:
                approvalContent
            case .approved:
                resultView(icon: "checkmark.circle.fill", color: .green, message: "Approved")
            case .denied:
                resultView(icon: "xmark.circle.fill", color: .red, message: "Denied")
            case .expired:
                resultView(icon: "clock.badge.xmark.fill", color: .orange, message: "Expired")
            case .flagged:
                resultView(icon: "flag.fill", color: .red, message: "Flagged as suspicious")
            }
        }
        .onChange(of: viewModel.state) { _, state in
            switch state {
            case .approved, .denied, .expired, .flagged:
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { dismiss() }
            default: break
            }
        }
    }

    // MARK: - Approval UI

    private var approvalContent: some View {
        ScrollView {
            VStack(spacing: 0) {
                // Header bar
                HStack {
                    Spacer()
                    Button("Deny") { viewModel.deny() }
                        .foregroundStyle(.red)
                        .padding()
                }

                // Service info
                VStack(spacing: 8) {
                    Image(systemName: "globe")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)

                    Text(request.serviceDisplayName)
                        .font(.title2.bold())

                    Text("wants you to log in as")
                        .foregroundStyle(.secondary)

                    Text(viewModel.activePersonaLabel)
                        .font(.headline)
                        .foregroundStyle(.blue)
                }

                // Scopes
                if !request.requesting.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Sharing:")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        ForEach(request.requesting, id: \.self) { scope in
                            Label(scope, systemImage: "checkmark.circle.fill")
                                .font(.callout)
                                .foregroundStyle(.green)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color(.systemGray6))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .padding(.horizontal)
                    .padding(.top, 16)
                }

                // Timer ring
                TimerRingView(seconds: viewModel.secondsRemaining, total: 30)
                    .frame(width: 64, height: 64)
                    .padding()

                // Approve button
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
                .disabled(viewModel.state == .authenticating)
                .padding(.horizontal)

                if viewModel.state == .authenticating {
                    ProgressView("Authenticating…").padding()
                }

                if let error = viewModel.errorMessage {
                    Text(error).font(.caption).foregroundStyle(.red).padding(.horizontal)
                }

                // Footer
                VStack(spacing: 8) {
                    if let location = request.locationHint {
                        Label(location, systemImage: "location.fill")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Button("This wasn't me") { viewModel.reportSuspicious() }
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 32)
                .padding(.bottom, 32)
            }
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

// MARK: - Timer Ring

struct TimerRingView: View {
    let seconds: Int
    let total: Int

    var body: some View {
        ZStack {
            Circle().stroke(Color(.systemGray5), lineWidth: 5)
            Circle()
                .trim(from: 0, to: Double(seconds) / Double(total))
                .stroke(seconds > 10 ? Color.blue : Color.red, lineWidth: 5)
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: seconds)
            Text("\(seconds)")
                .font(.system(.callout, design: .monospaced).bold())
                .foregroundStyle(seconds > 10 ? Color.primary : Color.red)
        }
    }
}
