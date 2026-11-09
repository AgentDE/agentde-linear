// swift-tools-version:5.10
import PackageDescription

// Linear in AgentDE: workstream tickets show their Linear state, and a widget lists your open issues.
let package = Package(
    name: "agentde-linear",
    platforms: [.macOS(.v14)],
    products: [.library(name: "AgentDELinear", targets: ["AgentDELinear"])],
    dependencies: [.package(path: "../agentde"), .package(path: "../agentde-widgets")],
    targets: [
        .target(name: "AgentDELinear",
                dependencies: [.product(name: "AgentDEKit", package: "agentde"), .product(name: "AgentDEWidgets", package: "agentde-widgets")],
                path: "Sources/AgentDELinear"),
        .testTarget(name: "AgentDELinearTests", dependencies: ["AgentDELinear"], path: "Tests/AgentDELinearTests"),
    ]
)
