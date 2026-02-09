// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "jwt-key-rotation",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(
            name: "JWTKeyRotation",
            targets: ["JWTKeyRotation"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", branch: "key-removal")
    ],
    targets: [
        .target(
            name: "JWTKeyRotation",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit")
            ]
        ),
        .testTarget(
            name: "JWTKeyRotationTests",
            dependencies: [
                "JWTKeyRotation",
                .product(name: "JWTKit", package: "jwt-kit"),
            ]
        ),
    ]
)
