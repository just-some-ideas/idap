// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IDAPAuth",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "IDAPAuth", targets: ["IDAPAuth"]),
    ],
    dependencies: [
        .package(path: "../idap-crypto"),
        .package(path: "../idap-identity"),
        .package(url: "https://github.com/groue/GRDB.swift", from: "6.0.0"),
    ],
    targets: [
        .target(name: "IDAPAuth", dependencies: [
            .product(name: "IDAPCrypto", package: "idap-crypto"),
            .product(name: "IDAPIdentity", package: "idap-identity"),
            .product(name: "GRDB", package: "GRDB.swift"),
        ]),
        .testTarget(name: "IDAPAuthTests", dependencies: ["IDAPAuth"]),
    ]
)
