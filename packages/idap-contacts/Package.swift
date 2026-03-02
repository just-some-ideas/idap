// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IDAPContacts",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "IDAPContacts", targets: ["IDAPContacts"]),
    ],
    dependencies: [
        .package(path: "../idap-crypto"),
        .package(path: "../idap-identity"),
        .package(url: "https://github.com/groue/GRDB.swift", from: "6.0.0"),
    ],
    targets: [
        .target(name: "IDAPContacts", dependencies: [
            .product(name: "IDAPCrypto", package: "idap-crypto"),
            .product(name: "IDAPIdentity", package: "idap-identity"),
            .product(name: "GRDB", package: "GRDB.swift"),
        ]),
        .testTarget(name: "IDAPContactsTests", dependencies: ["IDAPContacts"]),
    ]
)
