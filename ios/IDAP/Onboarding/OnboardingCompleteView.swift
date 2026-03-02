import SwiftUI

struct OnboardingCompleteView: View {
    @ObservedObject var viewModel: OnboardingViewModel
    let onComplete: () -> Void

    var body: some View {
        VStack(spacing: 32) {
            Spacer()

            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 80))
                .foregroundStyle(.green)

            Text("You're Set Up!")
                .font(.largeTitle.bold())

            Text("Your identity is secure. Now let's create your first persona.")
                .font(.body)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            Button("Create My Identity") {
                viewModel.completeOnboarding()
                onComplete()
            }
            .buttonStyle(.borderedProminent)
            .frame(maxWidth: .infinity)
            .padding(.horizontal)

            Spacer()
        }
        .padding()
    }
}
