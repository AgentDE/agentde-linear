import AgentDEKit
import AgentDEWidgets
import AppKit
import SwiftUI

/// Linear as a native extension: a ticket provider (workstream tickets show their state) and the "My issues"
/// widget, signed in through Linear's own sign-in or with an API key.
public final class LinearExtension: AgentDEExtension, TicketProvider, WidgetProvider {
    public let id = "linear"
    public let name = "Linear"
    let feed = LinearFeed()

    public init() {}

    public var ticketProviders: [TicketProvider] { [self] }

    public func settingsView() -> AnyView? { AnyView(Form { LinearKeyField() }.formStyle(.grouped).environment(feed)) }

    /// Your open Linear issues.
    public var widgets: [WidgetDefinition] {
        [WidgetDefinition(id: "linear", name: "Linear") { [feed] in AnyView(LinearWidget().environment(feed)) }]
    }

    // MARK: TicketProvider

    public var tracker: String { "linear" }
    public var isReady: Bool { feed.connected }
    public func claims(identifier: String) -> Bool { LinearAPI.isKey(identifier) }

    public func lookUp(_ identifiers: [String], completion: @escaping ([TicketInfo]) -> Void) {
        feed.lookUp(identifiers) { issues in DispatchQueue.main.async { completion(issues.map(Self.info)) } }
    }

    public func myTickets(completion: @escaping ([TicketInfo]) -> Void) {
        feed.loadIfNeeded()
        completion(feed.issues.map(Self.info))
    }

    static func info(_ issue: LinearIssue) -> TicketInfo {
        let digits = issue.stateColor.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        return TicketInfo(identifier: issue.identifier, title: issue.title, url: issue.url, state: issue.stateName,
                          stateType: issue.stateType, colorHex: UInt32(digits, radix: 16), priority: issue.priority)
    }
}

/// Linear: signed in (through Linear's MCP server) or an API key, either kept in the Keychain; or a Sign in
/// button, with a field for an API key as the alternative.
private struct LinearKeyField: View {
    @Environment(LinearFeed.self) private var feed
    @State private var key = ""
    @State private var useKey = false

    var body: some View {
        if feed.connected {
            LabeledContent("Linear") {
                HStack {
                    Text(feed.usesAPIKey ? (feed.viewer.map { "Connected as \($0)" } ?? feed.problem?.message ?? "Connected with an API key")
                                         : (feed.problem?.message ?? feed.viewer.map { "Signed in as \($0)" } ?? "Signed in"))
                        .foregroundStyle(.secondary).lineLimit(1)
                    Button(feed.usesAPIKey ? "Remove Key" : "Sign Out") { feed.usesAPIKey ? feed.setKey(nil) : feed.signOut() }
                }
            }
            .onAppear { feed.loadIfNeeded() }
        } else {
            LabeledContent("Linear") {
                HStack {
                    if feed.signingIn { Text("Finish in your browser…").foregroundStyle(.secondary) }
                    Button("Sign in with Linear") { feed.signIn() }.disabled(feed.signingIn)
                }
            }
            if let problem = feed.problem, problem != .noKey {
                Text(problem.message).font(.system(size: 11)).foregroundStyle(.secondary)
            }
            DisclosureGroup("Use an API key instead", isExpanded: $useKey) {
                HStack {
                    SecureField("lin_api_…", text: $key)
                    Button("Save") { feed.setKey(key); key = "" }.disabled(key.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Text("Create one in Linear › Settings › Security & access › Personal API keys.")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Text("For the Linear widget and tickets. Signing in opens Linear in your browser; what it gives \(AppBrand.name) is kept in your Keychain.")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
    }
}
