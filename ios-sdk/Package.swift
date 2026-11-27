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
        .library(name: "KeyAuthSDK", type: .dynamic, targets: ["KeyAuthSDK", "KeyAuthBridge", "KTImGuiOverlay"])
    ],
    targets: [
        .target(name: "KeyAuthSDK"),
        .target(
            name: "KTImGuiOverlay",
            publicHeadersPath: "include",
            cxxSettings: [
                .headerSearchPath("Vendor/imgui"),
                .headerSearchPath("Vendor/imgui/backends"),
                .define("IMGUI_DISABLE_OBSOLETE_FUNCTIONS"),
                .unsafeFlags(["-fvisibility=hidden"]),
            ],
            linkerSettings: [
                .linkedFramework("Metal"),
                .linkedFramework("QuartzCore"),
                .linkedFramework("MetalKit", .when(platforms: [.iOS])),
                .linkedFramework("UIKit", .when(platforms: [.iOS])),
                .linkedLibrary("c++"),
            ]
        ),
        .target(
            name: "KeyAuthBridge",
            dependencies: ["KeyAuthSDK", "KTImGuiOverlay"],
            publicHeadersPath: "include"
        ),
        .testTarget(name: "KeyAuthSDKTests", dependencies: ["KeyAuthSDK"])
    ],
    cxxLanguageStandard: .cxx17
)
