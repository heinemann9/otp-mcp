// swift-tools-version:5.10
import PackageDescription
let package = Package(
    name: "otp-mcp",
    platforms: [.macOS(.v14)],
    targets: [.executableTarget(name: "otp-mcp", path: "Sources/otp-mcp")]
)
