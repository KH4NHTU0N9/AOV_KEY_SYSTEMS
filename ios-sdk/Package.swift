// swift-tools-version: 5.9
// ios-sdk/Package.swift
import PackageDescription

let package = Package(
    name: "KeyAuthSDK",
    platforms: [
        .iOS(.v14),
        .macOS(.v12)
    ],
    products: [
        .library(name: "KeyAuthSDK", type: .dynamic, targets: ["KeyAuthSDK", "KeyAuthBridge"])
    ],
    targets: [
        .target(name: "KeyAuthSDK"),
        .target(
            name: "KeyAuthBridge",
            dependencies: ["KeyAuthSDK"],
            publicHeadersPath: "include"
        ),
        .testTarget(name: "KeyAuthSDKTests", dependencies: ["KeyAuthSDK"])
    ]
)
