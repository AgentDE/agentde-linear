import AgentDEKit
import Foundation
import Observation
import Security

/// A Linear issue, as the widget and workstreams show it.
struct LinearIssue: Codable, Equatable, Identifiable {
    var id: String
    /// "ENG-123".
    var identifier: String
    var title: String
    var url: String
    /// 0 none, 1 urgent, 2 high, 3 medium, 4 low.
    var priority: Int
    var stateName: String
    /// Linear's workflow state type: triage, backlog, unstarted, started, completed, canceled.
    var stateType: String
    /// "#f2c94c".
    var stateColor: String
    var updatedAt: Date?
}

/// Linear's GraphQL API with a personal API key (Linear › Settings › Security & access › Personal API keys),
/// kept in the login Keychain.
enum LinearAPI {
    static let endpoint = URL(string: "https://api.linear.app/graphql")!

    /// A Linear issue key ("ENG-123"): safe to put in a query.
    static func isKey(_ text: String) -> Bool { text.range(of: #"^[A-Z][A-Z0-9]{0,9}-[0-9]{1,7}$"#, options: .regularExpression) != nil }
    private static let keychainService = (Bundle.main.bundleIdentifier ?? "dev.agentde.AgentDE") + ".linear"

    /// Only the app itself uses the Keychain. The test runner isn't an app, and reading the app's items
    /// from it made macOS ask for the login password.
    static var keychainUsable: Bool { Bundle.main.bundlePath.hasSuffix(".app") }

    static var apiKey: String? {
        get {
            guard keychainUsable else { return nil }
            let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService,
                                        kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
            var result: AnyObject?
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
            return String(data: data, encoding: .utf8)
        }
        set {
            guard keychainUsable else { return }
            let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService]
            SecItemDelete(base as CFDictionary)
            guard let newValue, !newValue.isEmpty else { return }
            var item = base
            item[kSecAttrAccount as String] = "api-key"
            item[kSecValueData as String] = Data(newValue.utf8)
            SecItemAdd(item as CFDictionary, nil)
        }
    }

    static let issueFields = "id identifier title url priority updatedAt state { name type color }"

    /// Runs a query; the result's `data`, or the reason it failed.
    static func query(_ query: String, variables: [String: Any] = [:], key: String? = apiKey,
                      completion: @escaping (Result<[String: Any], LinearError>) -> Void) {
        guard let key else { return completion(.failure(.noKey)) }
        var request = URLRequest(url: endpoint, timeoutInterval: 20)
        request.httpMethod = "POST"
        request.setValue(key, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["query": query, "variables": variables])
        URLSession.shared.dataTask(with: request) { data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode
            let object = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            let result: Result<[String: Any], LinearError>
            if let error = error as? URLError {
                result = .failure(error.code == .notConnectedToInternet || error.code == .networkConnectionLost ? .offline : .other(error.localizedDescription))
            } else if status == 401 || status == 403 {
                result = .failure(.badKey)
            } else if let data = object?["data"] as? [String: Any], !data.isEmpty {
                result = .success(data)   // possibly partial: an issue that wasn't found is null, with an error beside it
            } else if let errors = object?["errors"] as? [[String: Any]], let message = errors.first?["message"] as? String {
                result = message.localizedCaseInsensitiveContains("authenticat") ? .failure(.badKey) : .failure(.other(message))
            } else {
                result = .failure(.other("Linear HTTP \(status ?? 0)"))
            }
            DispatchQueue.main.async { completion(result) }
        }.resume()
    }

    static func issue(from node: [String: Any]) -> LinearIssue? {
        guard let id = node["id"] as? String, let identifier = node["identifier"] as? String,
              let title = node["title"] as? String, let url = node["url"] as? String else { return nil }
        let state = node["state"] as? [String: Any] ?? [:]
        return LinearIssue(id: id, identifier: identifier, title: title, url: url, priority: node["priority"] as? Int ?? 0,
                           stateName: state["name"] as? String ?? "", stateType: state["type"] as? String ?? "",
                           stateColor: state["color"] as? String ?? "#95a2b3",
                           updatedAt: (node["updatedAt"] as? String).flatMap { ISO8601DateFormatter.withFractions.date(from: $0) })
    }
}

enum LinearError: Error, Equatable {
    case noKey, badKey, signedOut, offline, other(String)

    var message: String {
        switch self {
        case .noKey: "Sign in to Linear in Settings › Widgets."
        case .badKey: "Linear didn't accept the API key. Check it in Settings › Widgets."
        case .signedOut: "Linear signed \(AppBrand.name) out. Sign in again."
        case .offline: "Offline"
        case .other(let text): text
        }
    }
}

extension ISO8601DateFormatter {
    static let withFractions: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }()
}

/// The issues assigned to you that aren't done or canceled, most urgent first; refreshed every few minutes
/// while the widget shows. Read with the API key when there is one, else through the Linear sign-in
/// (`LinearMCP`).
@Observable
final class LinearFeed {
    private(set) var issues: [LinearIssue] = []
    private(set) var problem: LinearError?
    private(set) var viewer: String?
    @ObservationIgnored private var loadedAt: Date?
    /// When the issues last loaded successfully (cached ones show it while Linear can't be reached).
    private(set) var updatedAt: Date?
    @ObservationIgnored private var loading = false

    /// An API key or a sign-in.
    private(set) var connected = LinearAPI.apiKey != nil || LinearMCP.shared.signedIn
    private(set) var usesAPIKey = LinearAPI.apiKey != nil
    private(set) var signingIn = false

    func loadIfNeeded(force: Bool = false) {
        if loading || (!force && (loadedAt.map { Date().timeIntervalSince($0) < 180 } ?? false)) { return }
        loading = true
        if !usesAPIKey {
            LinearMCP.shared.callTool("list_issues", ["assignee": "me", "limit": 50]) { [weak self] result in
                guard let self else { return }
                self.loading = false
                self.loadedAt = Date()
                switch result {
                case .success(let json):
                    let open = LinearMCP.issues(in: json).filter { !["completed", "canceled"].contains($0.stateType) }
                    self.issues = Self.sorted(open)
                    self.problem = nil
                    self.updatedAt = Date()
                    if self.viewer == nil { self.lookUpViewer() }
                case .failure(let error):
                    DebugLog.log("Linear list_issues: \(error.message)", "linear")
                    self.problem = error
                    if error == .signedOut { self.connected = false }
                    if error != .offline { self.issues = [] }
                }
            }
            return
        }
        let query = """
        query { viewer { name assignedIssues(first: 50, orderBy: updatedAt, filter: { state: { type: { nin: ["completed", "canceled"] } } }) { nodes { \(LinearAPI.issueFields) } } } }
        """
        LinearAPI.query(query) { [weak self] result in
            guard let self else { return }
            self.loading = false
            self.loadedAt = Date()
            switch result {
            case .success(let data):
                let viewer = data["viewer"] as? [String: Any]
                self.viewer = viewer?["name"] as? String
                let nodes = (viewer?["assignedIssues"] as? [String: Any])?["nodes"] as? [[String: Any]] ?? []
                self.issues = Self.sorted(nodes.compactMap(LinearAPI.issue(from:)))
                self.updatedAt = Date()
                self.problem = nil
            case .failure(let error):
                self.problem = error
                if error != .offline { self.issues = [] }
            }
        }
    }

    /// Started first, then by priority (urgent first, none last), then most recently updated.
    static func sorted(_ issues: [LinearIssue]) -> [LinearIssue] {
        let stage = ["started": 0, "unstarted": 1, "triage": 2, "backlog": 3]
        return issues.sorted {
            let a = (stage[$0.stateType] ?? 4, $0.priority == 0 ? 5 : $0.priority), b = (stage[$1.stateType] ?? 4, $1.priority == 0 ? 5 : $1.priority)
            if a != b { return a < b }
            return ($0.updatedAt ?? .distantPast) > ($1.updatedAt ?? .distantPast)
        }
    }

    /// Who the sign-in is for ("Ada Lovelace · ada@example.com"), so Settings shows which Linear account it is.
    private func lookUpViewer() {
        LinearMCP.shared.callTool("get_user", ["query": "me"]) { [weak self] result in
            guard let self else { return }
            guard case .success(let json) = result, let user = Self.person(in: json) else {
                DebugLog.log("Linear get_user: \(String(describing: result).prefix(300))", "linear")
                return
            }
            self.viewer = [user.name, user.email].compactMap { $0 }.joined(separator: " · ")
        }
    }

    /// The first object with a name or an email, wherever it sits in a tool result.
    static func person(in json: Any) -> (name: String?, email: String?)? {
        if let object = json as? [String: Any] {
            let name = (object["displayName"] ?? object["name"]) as? String, email = object["email"] as? String
            if email != nil || (name != nil && object["identifier"] == nil) { return (name, email) }
            for value in object.values { if let found = person(in: value) { return found } }
        } else if let array = json as? [Any] {
            for value in array { if let found = person(in: value) { return found } }
        }
        return nil
    }

    /// Workstream tickets by identifier, as last looked up (state, title, link).
    private(set) var tickets: [String: LinearIssue] = [:]
    @ObservationIgnored private var lookedUp: [String: Date] = [:]

    /// Looks up the tickets not looked up in the last 5 minutes, in one request; `found` gets the ones Linear has.
    func lookUp(_ identifiers: [String], found: @escaping ([LinearIssue]) -> Void = { _ in }) {
        guard connected else { return }
        let now = Date()
        let due = identifiers.filter { id in lookedUp[id].map { now.timeIntervalSince($0) > 300 } ?? true }
            .filter(LinearAPI.isKey)   // safe to put in the query
        guard !due.isEmpty else { return }
        for id in due { lookedUp[id] = now }
        if !usesAPIKey {
            var collected: [LinearIssue] = []
            var left = due.count
            for id in due {
                LinearMCP.shared.callTool("get_issue", ["id": id]) { [weak self] result in
                    if case .success(let json) = result, let issue = LinearMCP.issues(in: json).first(where: { $0.identifier == id }) {
                        self?.tickets[id] = issue
                        collected.append(issue)
                    }
                    left -= 1
                    if left == 0 { found(collected) }
                }
            }
            return
        }
        let fields = due.enumerated().map { "i\($0.offset): issue(id: \"\($0.element)\") { \(LinearAPI.issueFields) }" }.joined(separator: " ")
        LinearAPI.query("query { \(fields) }") { [weak self] result in
            guard let self, case .success(let data) = result else { return }
            let issues = data.values.compactMap { ($0 as? [String: Any]).flatMap(LinearAPI.issue(from:)) }
            for issue in issues { self.tickets[issue.identifier] = issue }
            found(issues)
        }
    }

    /// Linear's approve page in the browser; connected once it redirects back.
    func signIn(completion: @escaping (LinearError?) -> Void = { _ in }) {
        signingIn = true
        LinearMCP.shared.signIn { [weak self] result in
            guard let self else { return }
            self.signingIn = false
            if case .failure(let error) = result { self.problem = error; return completion(error) }
            self.reset()
            completion(nil)
        }
    }

    func signOut() {
        LinearMCP.shared.signOut()
        reset()
    }

    func setKey(_ key: String?) {
        LinearAPI.apiKey = key?.trimmingCharacters(in: .whitespacesAndNewlines)
        reset()
    }

    private func reset() {
        connected = LinearAPI.apiKey != nil || LinearMCP.shared.signedIn
        usesAPIKey = LinearAPI.apiKey != nil
        issues = []
        viewer = nil
        problem = nil
        tickets = [:]
        lookedUp = [:]
        loadIfNeeded(force: true)
    }
}
