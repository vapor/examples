// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "jwt-key-rotation",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .library(
            name: "JWTKeyRotation",
            targets: ["JWTKeyRotation"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.4.0"),
    ],
    targets: [
        .target(
            name: "JWTKeyRotation",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
            ]
        ),
        .testTarget(
            name: "JWTKeyRotationTests",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .target(name: "JWTKeyRotation"),
            ]
        ),
    ]
)
