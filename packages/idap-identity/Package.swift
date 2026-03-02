// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IDAPIdentity",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "IDAPIdentity", targets: ["IDAPIdentity"]),
    ],
    dependencies: [
        .package(path: "../idap-crypto"),
        .package(url: "https://github.com/groue/GRDB.swift", from: "6.0.0"),
    ],
    targets: [
        .target(name: "IDAPIdentity", dependencies: [
            .product(name: "IDAPCrypto", package: "idap-crypto"),
            .product(name: "GRDB", package: "GRDB.swift"),
        ]),
        .testTarget(name: "IDAPIdentityTests", dependencies: ["IDAPIdentity"]),
    ]
)
