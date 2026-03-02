// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IDAPRecovery",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "IDAPRecovery", targets: ["IDAPRecovery"]),
    ],
    dependencies: [
        .package(path: "../idap-crypto"),
        .package(path: "../idap-contacts"),
    ],
    targets: [
        .target(name: "IDAPRecovery", dependencies: [
            .product(name: "IDAPCrypto", package: "idap-crypto"),
            .product(name: "IDAPContacts", package: "idap-contacts"),
        ]),
        .testTarget(name: "IDAPRecoveryTests", dependencies: ["IDAPRecovery"]),
    ]
)
