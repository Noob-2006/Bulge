// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "tauri-plugin-seagent-mobile",
  platforms: [
    .macOS(.v10_13),
    .iOS(.v14),
  ],
  products: [
    .library(
      name: "tauri-plugin-seagent-mobile",
      type: .static,
      targets: ["tauri-plugin-seagent-mobile"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-seagent-mobile",
      dependencies: [
        .byName(name: "Tauri")
      ],
      path: "Sources")
  ]
)
