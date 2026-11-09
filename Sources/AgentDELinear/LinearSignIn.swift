import AgentDEKit
import AppKit
import CryptoKit
import Foundation
import Network
import Security

/// Signing in to Linear without an API key, through Linear's MCP server (`mcp.linear.app`), which lets any app
/// register itself (OAuth dynamic client registration) and sign in with PKCE. The browser shows Linear's own
/// approve screen and redirects to a one-time listener on 127.0.0.1. The tokens are for the MCP server, so
/// issues are read through its tools (`list_issues`, `get_issue`), not the GraphQL API an API key uses.
final class LinearMCP {
    static let shared = LinearMCP()

    private static let base = URL(string: "https://mcp.linear.app")!
    private static let endpoint = URL(string: "https://mcp.linear.app/mcp")!
    private static let keychainService = (Bundle.main.bundleIdentifier ?? "dev.agentde.AgentDE") + ".linear-oauth"

    struct Tokens: Codable {
        var clientID: String
        var redirectURI: String
        var accessToken: String
        var refreshToken: String?
        var expiresAt: Date?
    }

    private(set) var tokens: Tokens? = LinearMCP.loadTokens()
    var signedIn: Bool { tokens != nil }
    private var session: String?
    private var listener: NWListener?
    private var loggedTools = false

    // MARK: Sign-in

    /// Registers AgentDE with Linear, opens Linear's approve page in the browser and waits (up to 5 minutes)
    /// for it to redirect back. Calls back on the main queue.
    func signIn(completion: @escaping (Result<Void, LinearError>) -> Void) {
        listener?.cancel()
        let verifier = Self.randomString(48)
        let challenge = Data(SHA256.hash(data: Data(verifier.utf8))).base64URL
        let state = Self.randomString(24)
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        guard let listener = try? NWListener(using: parameters) else { return completion(.failure(.other("Couldn't start the sign-in listener."))) }
        self.listener = listener
        var finished = false
        let finish = { [weak self] (result: Result<Void, LinearError>) in
            DispatchQueue.main.async {
                guard !finished else { return }
                finished = true
                listener.cancel()   // this attempt's, even if another has started since
                if self?.listener === listener { self?.listener = nil }
                completion(result)
            }
        }
        var redirect = ""
        var clientID = ""
        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: .main)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { data, _, _, _ in
                let request = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                let query = Self.callbackQuery(request)
                let ok = query["state"] == state && query["code"] != nil
                let page = ok ? "Signed in to Linear. You can close this tab and go back to \(AppBrand.name)."
                              : "\(AppBrand.name) couldn't sign in to Linear\(query["error"].map { " (\($0))" } ?? ""). You can close this tab."
                let body = "<!doctype html><meta charset=utf-8><title>\(AppBrand.name)</title><body style=\"font:15px -apple-system;padding:40px\">\(page)</body>"
                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
                guard !request.isEmpty, request.hasPrefix("GET /callback") else { return }
                guard ok, let code = query["code"] else { return finish(.failure(.other(query["error"] ?? "Linear didn't approve the sign-in."))) }
                self?.exchange(code: code, verifier: verifier, clientID: clientID, redirect: redirect, completion: finish)
            }
        }
        listener.stateUpdateHandler = { [weak self] listenerState in
            guard case .ready = listenerState, let port = listener.port?.rawValue, redirect.isEmpty else {
                if case .failed = listenerState { finish(.failure(.other("The sign-in listener stopped."))) }
                return
            }
            redirect = "http://127.0.0.1:\(port)/callback"
            self?.register(redirect: redirect) { result in
                switch result {
                case .failure(let error): finish(.failure(error))
                case .success(let id):
                    clientID = id
                    var components = URLComponents(url: Self.base.appendingPathComponent("authorize"), resolvingAgainstBaseURL: false)!
                    components.queryItems = [
                        URLQueryItem(name: "response_type", value: "code"), URLQueryItem(name: "client_id", value: id),
                        URLQueryItem(name: "redirect_uri", value: redirect), URLQueryItem(name: "code_challenge", value: challenge),
                        URLQueryItem(name: "code_challenge_method", value: "S256"), URLQueryItem(name: "state", value: state),
                        URLQueryItem(name: "scope", value: "read write"), URLQueryItem(name: "resource", value: Self.endpoint.absoluteString),
                    ]
                    DispatchQueue.main.async { NSWorkspace.shared.open(components.url!) }
                }
            }
        }
        listener.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + 300) { finish(.failure(.other("The sign-in timed out."))) }
    }

    func signOut() {
        tokens = nil
        session = nil
        Self.saveTokens(nil)
    }

    private func register(redirect: String, completion: @escaping (Result<String, LinearError>) -> Void) {
        let body: [String: Any] = ["client_name": AppBrand.name, "redirect_uris": [redirect], "grant_types": ["authorization_code", "refresh_token"],
                                   "response_types": ["code"], "token_endpoint_auth_method": "none"]
        post(Self.base.appendingPathComponent("register"), json: body) { result in
            completion(result.flatMap { object in
                (object["client_id"] as? String).map { .success($0) } ?? .failure(.other("Linear didn't register \(AppBrand.name)."))
            })
        }
    }

    private func exchange(code: String, verifier: String, clientID: String, redirect: String, completion: @escaping (Result<Void, LinearError>) -> Void) {
        let form = ["grant_type": "authorization_code", "code": code, "redirect_uri": redirect, "client_id": clientID,
                    "code_verifier": verifier, "resource": Self.endpoint.absoluteString]
        post(Self.base.appendingPathComponent("token"), form: form) { [weak self] result in
            switch result {
            case .failure(let error): completion(.failure(error))
            case .success(let object):
                guard let self, let access = object["access_token"] as? String else { return completion(.failure(.other("Linear didn't send a token."))) }
                self.store(Tokens(clientID: clientID, redirectURI: redirect, accessToken: access, refreshToken: object["refresh_token"] as? String,
                                  expiresAt: (object["expires_in"] as? Double).map { Date().addingTimeInterval($0) }))
                DebugLog.log("signed in to Linear's MCP server", "linear")
                completion(.success(()))
            }
        }
    }

    /// A fresh access token, refreshing it when it's (about to be) expired.
    private func withToken(forceRefresh: Bool = false, _ body: @escaping (Result<String, LinearError>) -> Void) {
        guard let tokens else { return body(.failure(.noKey)) }
        let stale = forceRefresh || (tokens.expiresAt.map { $0.timeIntervalSinceNow < 60 } ?? false)
        guard stale else { return body(.success(tokens.accessToken)) }
        guard let refresh = tokens.refreshToken else { signOut(); return body(.failure(.signedOut)) }
        post(Self.base.appendingPathComponent("token"), form: ["grant_type": "refresh_token", "refresh_token": refresh,
                                                              "client_id": tokens.clientID, "resource": Self.endpoint.absoluteString]) { [weak self] result in
            guard let self else { return }
            guard case .success(let object) = result, let access = object["access_token"] as? String else {
                if case .failure(.offline) = result { return body(.failure(.offline)) }
                self.signOut()
                return body(.failure(.signedOut))
            }
            var updated = tokens
            updated.accessToken = access
            updated.refreshToken = object["refresh_token"] as? String ?? tokens.refreshToken
            updated.expiresAt = (object["expires_in"] as? Double).map { Date().addingTimeInterval($0) }
            self.store(updated)
            body(.success(access))
        }
    }

    private func store(_ tokens: Tokens) {
        self.tokens = tokens
        Self.saveTokens(tokens)
    }

    // MARK: Tools

    /// Calls one of the MCP server's tools; the result's content, parsed as JSON where it is JSON.
    func callTool(_ name: String, _ arguments: [String: Any], completion: @escaping (Result<Any, LinearError>) -> Void) {
        withToken { [weak self] token in
            guard let self else { return }
            switch token {
            case .failure(let error): completion(.failure(error))
            case .success(let token):
                self.ensureSession(token: token) { ready in
                    if case .failure(let error) = ready { return completion(.failure(error)) }
                    self.rpc(token: token, ["jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": ["name": name, "arguments": arguments]]) { result in
                        switch result {
                        case .failure(.signedOut):
                            // An expired session or token: start over once.
                            self.session = nil
                            self.withToken(forceRefresh: true) { _ in
                                guard self.tokens != nil else { return completion(.failure(.signedOut)) }
                                self.callTool(name, arguments, completion: completion)
                            }
                        case .failure(let error): completion(.failure(error))
                        case .success(let response):
                            let result = response["result"] as? [String: Any] ?? [:]
                            if let error = response["error"] as? [String: Any] { return completion(.failure(.other(error["message"] as? String ?? "Linear error"))) }
                            if let structured = result["structuredContent"] { return completion(.success(structured)) }
                            let texts = (result["content"] as? [[String: Any]] ?? []).compactMap { $0["text"] as? String }
                            if result["isError"] as? Bool == true { return completion(.failure(.other(texts.first ?? "Linear error"))) }
                            let parsed: [Any] = texts.map { text in (try? JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed])) ?? text }
                            completion(.success(parsed.count == 1 ? parsed[0] : parsed))
                        }
                    }
                }
            }
        }
    }

    private func ensureSession(token: String, _ done: @escaping (Result<Void, LinearError>) -> Void) {
        if session != nil { return done(.success(())) }
        rpc(token: token, ["jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [
            "protocolVersion": "2025-06-18", "capabilities": [:], "clientInfo": ["name": AppBrand.name, "version": "1"]]]) { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error): done(.failure(error))
            case .success:
                self.rpc(token: token, ["jsonrpc": "2.0", "method": "notifications/initialized"]) { _ in }
                if !self.loggedTools {
                    self.loggedTools = true
                    self.rpc(token: token, ["jsonrpc": "2.0", "id": 9, "method": "tools/list"]) { listed in
                        if case .success(let object) = listed {
                            let tools = ((object["result"] as? [String: Any])?["tools"] as? [[String: Any]] ?? []).compactMap { $0["name"] as? String }
                            DebugLog.log("Linear MCP tools: \(tools.joined(separator: ", "))", "linear")
                        }
                    }
                }
                done(.success(()))
            }
        }
    }

    /// One JSON-RPC message over streamable HTTP; the reply comes as JSON or as server-sent events.
    private func rpc(token: String, _ message: [String: Any], completion: @escaping (Result<[String: Any], LinearError>) -> Void) {
        var request = URLRequest(url: Self.endpoint, timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json, text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("2025-06-18", forHTTPHeaderField: "MCP-Protocol-Version")
        if let session { request.setValue(session, forHTTPHeaderField: "Mcp-Session-Id") }
        request.httpBody = try? JSONSerialization.data(withJSONObject: message)
        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            let http = response as? HTTPURLResponse
            DispatchQueue.main.async {
                if let id = http?.value(forHTTPHeaderField: "Mcp-Session-Id") { self?.session = id }
                if let error = error as? URLError {
                    return completion(.failure(error.code == .notConnectedToInternet || error.code == .networkConnectionLost ? .offline : .other(error.localizedDescription)))
                }
                switch http?.statusCode ?? 0 {
                case 401, 404: return completion(.failure(.signedOut))   // 404: the session is gone
                case 200..<300: break
                case let status: return completion(.failure(.other("Linear HTTP \(status)")))
                }
                guard message["id"] != nil else { return completion(.success([:])) }
                let reply = Self.reply(data ?? Data(), contentType: http?.value(forHTTPHeaderField: "Content-Type") ?? "")
                completion(reply.map { .success($0) } ?? .failure(.other("Linear sent an unreadable reply.")))
            }
        }.resume()
    }

    /// The JSON-RPC response in a reply: the body itself, or the last `data:` event that is one.
    static func reply(_ data: Data, contentType: String) -> [String: Any]? {
        if !contentType.contains("event-stream") { return try? JSONSerialization.jsonObject(with: data) as? [String: Any] }
        let events = String(decoding: data, as: UTF8.self).components(separatedBy: "\n")
            .filter { $0.hasPrefix("data:") }.map { String($0.dropFirst(5)).trimmingCharacters(in: .whitespaces) }
        return events.reversed().lazy.compactMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any] }
            .first { $0["result"] != nil || $0["error"] != nil }
    }

    // MARK: Reading issues out of tool results

    /// Every issue in a tool result, wherever it sits: any object with an identifier and a title.
    static func issues(in json: Any) -> [LinearIssue] {
        var found: [LinearIssue] = []
        func walk(_ value: Any) {
            if let object = value as? [String: Any] {
                if let issue = issue(from: object) { found.append(issue); return }
                object.values.forEach(walk)
            } else if let array = value as? [Any] {
                array.forEach(walk)
            }
        }
        walk(json)
        var seen = Set<String>()
        return found.filter { seen.insert($0.identifier).inserted }
    }

    static func issue(from object: [String: Any]) -> LinearIssue? {
        // Linear's MCP server gives the key (ENG-1) as `id` and the UUID as `uuid`; the GraphQL API as `identifier` and `id`.
        guard let identifier = (object["identifier"] ?? object["id"]) as? String, LinearAPI.isKey(identifier),
              let title = object["title"] as? String else { return nil }
        let priority = (object["priority"] as? Int) ?? ((object["priority"] as? [String: Any])?["value"] as? Int) ?? 0
        let state = object["state"] ?? object["status"]
        let stateObject = state as? [String: Any]
        let name = (state as? String) ?? stateObject?["name"] as? String ?? ""
        let type = stateObject?["type"] as? String ?? object["statusType"] as? String ?? stateType(forName: name)
        return LinearIssue(id: object["uuid"] as? String ?? object["id"] as? String ?? identifier, identifier: identifier, title: title, url: object["url"] as? String ?? "",
                           priority: priority, stateName: name, stateType: type,
                           stateColor: stateObject?["color"] as? String ?? stateColor(forType: type),
                           updatedAt: (object["updatedAt"] as? String).flatMap {
                               ISO8601DateFormatter.withFractions.date(from: $0) ?? ISO8601DateFormatter().date(from: $0)
                           })
    }

    /// Linear's default workflow names, for results that give only a state's name.
    static func stateType(forName name: String) -> String {
        switch name.lowercased() {
        case "done", "completed", "merged", "released": "completed"
        case "canceled", "cancelled", "duplicate", "won't do", "wont do": "canceled"
        case "in progress", "in review", "started", "review": "started"
        case "todo", "to do", "unstarted": "unstarted"
        case "backlog": "backlog"
        case "triage": "triage"
        default: ""
        }
    }

    static func stateColor(forType type: String) -> String {
        switch type {
        case "started": "#f2c94c"
        case "unstarted": "#e2e2e2"
        case "completed": "#5e6ad2"
        case "triage": "#fc7840"
        default: "#95a2b3"
        }
    }

    // MARK: Plumbing

    private func post(_ url: URL, json: [String: Any]? = nil, form: [String: String]? = nil,
                      completion: @escaping (Result<[String: Any], LinearError>) -> Void) {
        var request = URLRequest(url: url, timeoutInterval: 30)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let json {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try? JSONSerialization.data(withJSONObject: json)
        } else if let form {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            var components = URLComponents()
            components.queryItems = form.map { URLQueryItem(name: $0.key, value: $0.value) }
            request.httpBody = components.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B").data(using: .utf8)
        }
        URLSession.shared.dataTask(with: request) { data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let object = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
            DispatchQueue.main.async {
                if let error = error as? URLError {
                    return completion(.failure(error.code == .notConnectedToInternet || error.code == .networkConnectionLost ? .offline : .other(error.localizedDescription)))
                }
                guard (200..<300).contains(status), let object else {
                    let reason = object?["error_description"] as? String ?? object?["error"] as? String ?? "Linear HTTP \(status)"
                    DebugLog.log("Linear sign-in: \(url.lastPathComponent) failed: \(reason)", "linear")
                    return completion(.failure(.other(reason)))
                }
                completion(.success(object))
            }
        }.resume()
    }

    static func callbackQuery(_ request: String) -> [String: String] {
        guard let line = request.components(separatedBy: "\r\n").first, line.hasPrefix("GET "),
              let target = line.split(separator: " ").dropFirst().first,
              let items = URLComponents(string: "http://127.0.0.1" + target)?.queryItems else { return [:] }
        return Dictionary(items.compactMap { item in item.value.map { (item.name, $0) } }, uniquingKeysWith: { a, _ in a })
    }

    private static func randomString(_ bytes: Int) -> String {
        var data = Data(count: bytes)
        _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, bytes, $0.baseAddress!) }
        return data.base64URL
    }

    private static func loadTokens() -> Tokens? {
        guard LinearAPI.keychainUsable else { return nil }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService,
                                    kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try? decoder.decode(Tokens.self, from: data)
    }

    private static func saveTokens(_ tokens: Tokens?) {
        guard LinearAPI.keychainUsable else { return }
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: keychainService]
        SecItemDelete(base as CFDictionary)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard let tokens, let data = try? encoder.encode(tokens) else { return }
        var item = base
        item[kSecAttrAccount as String] = "oauth"
        item[kSecValueData as String] = data
        SecItemAdd(item as CFDictionary, nil)
    }
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
