import SwiftUI
import IDAPAuth
import IDAPContacts

struct RootView: View {
    @EnvironmentObject var session: IDAPSession

    var body: some View {
        Group {
            if !session.isOnboarded {
                OnboardingCoordinatorView(session: session)
            } else if !session.isUnlocked {
                LockView()
            } else {
                ContentView()
            }
        }
        .sheet(item: Binding(
            get: { session.pendingAuthRequest },
            set: { session.pendingAuthRequest = $0 }
        )) { request in
            AuthApprovalView(request: request, session: session)
        }
        .sheet(item: Binding(
            get: { session.pendingCapabilityRequests.first },
            set: { newValue in
                if newValue == nil, let first = session.pendingCapabilityRequests.first {
                    session.pendingCapabilityRequests.removeAll { $0.requestId == first.requestId }
                }
            }
        )) { request in
            CapabilityRequestView(request: request, session: session)
        }
        .onOpenURL { url in
            session.handleDeepLink(url)
        }
    }
}

// Make AuthRequest Identifiable for sheet presentation
extension AuthRequest: @retroactive Identifiable {
    public var id: String { requestId }
}

// Make CapabilityRequest Identifiable for sheet presentation
extension CapabilityRequest: @retroactive Identifiable {
    public var id: String { requestId }
}
