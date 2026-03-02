// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IDAPCrypto",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "IDAPCrypto", targets: ["IDAPCrypto"]),
    ],
    targets: [
        .target(
            name: "IDAPCrypto",
            resources: [.process("Resources")]
        ),
        .testTarget(name: "IDAPCryptoTests", dependencies: ["IDAPCrypto"]),
    ]
)
