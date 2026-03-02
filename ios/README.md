# IDAP iOS App

SwiftUI iOS app — the reference client for the IDAP protocol. Links all five Swift packages and provides the full user experience: onboarding, persona management, auth approval, contacts, and recovery.

## Role in IDAP

This is the product-facing reference implementation. It demonstrates how the protocol works end-to-end: creating an identity, registering at a proxy, approving login requests via number-match, exchanging contacts via capability requests, and managing recovery. Everything sensitive lives on-device — the app uses Secure Enclave for seed protection and Keychain for encrypted storage.

## Architecture

`IDAPSession` is the central state hub — an `@MainActor` `ObservableObject` created in `AppDelegate` and injected via `@EnvironmentObject`. It holds references to all IDAP package instances and manages the master seed lifecycle.

### Key Components

| Component | Role |
|-----------|------|
| `IDAPSession` | App-wide state, package instances, WebSocket management |
| `DatabaseManager` | Provides file-backed GRDB database queues per package |
| `KeychainService` | Encrypted seed storage (Secure Enclave backed) |
| `ActivityStore` | Auth activity history |

### Package Integration

| Package | Used for |
|---------|----------|
| `IDAPCrypto` | Seed generation, key derivation, encryption |
| `IDAPIdentity` | Persona CRUD, credential wallet |
| `IDAPAuth` | Auth request handling, JWT signing, WebSocket |
| `IDAPContacts` | Capability-based contact exchange, contact storage |
| `IDAPRecovery` | Recovery map, shard management |

### App Flow

1. **Onboarding** — Generate seed, create Secure Enclave key, encrypt seed to Keychain, create first persona
2. **Main tabs** — Personas, Auth, Contacts, Activity, Settings
3. **Auth approval** — Receive auth request via WebSocket, display number-match, biometric confirm, sign JWT
4. **Contacts** — Access code sharing, capability request/grant exchange, encrypted messaging
5. **Recovery** — Shard distribution to contacts, recovery map management

## Building

### Prerequisites

- Xcode 15+
- [xcodegen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`

### First-Time Setup

```sh
cd ios
xcodegen generate
open IDAP.xcodeproj
```

Regenerate the project after any changes to `project.yml`.

### Build from Command Line

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project IDAP.xcodeproj -scheme IDAP \
    -sdk iphonesimulator \
    -destination "platform=iOS Simulator,name=iPhone 16" \
    build
```

## Testing

### Unit Tests

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild test \
    -project IDAP.xcodeproj -scheme IDAPTests \
    -sdk iphonesimulator \
    -destination "platform=iOS Simulator,name=iPhone 16" \
    | xcpretty
```

19 unit tests covering `OnboardingViewModel`, `PersonaCreationViewModel`, `AuthApprovalViewModel`, and `ContactsViewModel`. All mocked — no network, no keychain, no crypto required.

### UI Tests

UI tests require a running proxy:

```sh
# Terminal 1 — start proxy
cd proxy && go run ./cmd/idap-proxy --dev

# Terminal 2 — run UI tests
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild test \
    -project ios/IDAP.xcodeproj -scheme IDAPUITests \
    -sdk iphonesimulator \
    -destination "platform=iOS Simulator,name=iPhone 16"
```

## Capabilities

The app requires these entitlements (declared in `IDAP.entitlements` and `project.yml`):

| Capability | Required for | Status |
|-----------|-------------|--------|
| Keychain Sharing | Storing encrypted seed | Implemented |
| Face ID | Biometric approval gate | Implemented |
| Push Notifications | Auth approval notifications | *(planned)* |
| Background Modes (remote-notification) | Waking app on push | *(planned)* |
| Associated Domains (`webcredentials:idap.app`) | Passkey support | *(planned)* |

Simulator testing works for unit tests. UI tests and full auth flow require a device.

## Status

Implemented: full onboarding flow, persona management (create, edit, delete, multi-proxy), auth approval with number-match via WebSocket, contact exchange via capability requests, activity history, settings. Not yet implemented: passkey integration *(planned)*, multi-device sync *(planned)*, push notification handling *(planned)*, deep link processing *(planned)*.
