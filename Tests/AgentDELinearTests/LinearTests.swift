import Foundation
import Testing
@testable import AgentDELinear

@Suite("Linear sign-in")
struct LinearTests {
    @Test func readsTheCallback() {
        let request = "GET /callback?code=abc%2B1&state=xyz HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n\r\n"
        #expect(LinearMCP.callbackQuery(request) == ["code": "abc+1", "state": "xyz"])
        #expect(LinearMCP.callbackQuery("GET /favicon.ico HTTP/1.1\r\n\r\n").isEmpty)
        #expect(LinearMCP.callbackQuery("").isEmpty)
    }

    @Test func readsRepliesAsJSONOrEvents() {
        let json = Data(#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.utf8)
        #expect(LinearMCP.reply(json, contentType: "application/json")?["result"] != nil)
        let events = Data("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}\n\n".utf8)
        #expect(LinearMCP.reply(events, contentType: "text/event-stream")?["id"] as? Int == 2)
    }

    @Test func findsIssuesInToolResultsOfAnyShape() {
        let result: [String: Any] = ["issues": [
            ["id": "u1", "identifier": "ENG-1", "title": "Ship it", "url": "https://linear.app/a/issue/ENG-1/ship-it",
             "priority": ["value": 2, "name": "High"], "status": "In Progress", "updatedAt": "2026-10-20T10:00:00.000Z"],
            ["identifier": "ENG-2", "title": "Done one", "state": ["name": "Shipped", "type": "completed", "color": "#5e6ad2"], "priority": 0],
            ["identifier": "not an id", "title": "x"],
        ], "nextCursor": NSNull()]
        let issues = LinearMCP.issues(in: result)
        #expect(issues.map(\.identifier) == ["ENG-1", "ENG-2"])
        #expect(issues[0].priority == 2 && issues[0].stateType == "started" && issues[0].stateColor == "#f2c94c" && issues[0].updatedAt != nil)
        #expect(issues[1].stateType == "completed" && issues[1].stateName == "Shipped")
        #expect(LinearMCP.issues(in: [result, result]).count == 2)   // once each
    }

    @Test func readsTheMCPServersCurrentShape() {
        // As list_issues returns it today: the key as `id`, the UUID as `uuid`, the state as `status` + `statusType`.
        let result: [String: Any] = ["issues": [
            ["id": "ENG-101", "uuid": "00000000-0000-4000-8000-000000000101", "title": "Fix login redirect",
             "priority": ["value": 0, "name": "No priority"], "status": "TO DO", "statusType": "unstarted",
             "url": "https://linear.app/acme/issue/ENG-101/x", "updatedAt": "2026-01-15T12:00:00.000Z"],
            ["id": "ENG-102", "uuid": "00000102", "title": "Write release notes", "status": "Done", "statusType": "completed"],
        ], "hasNextPage": true]
        let issues = LinearMCP.issues(in: result)
        #expect(issues.map(\.identifier) == ["ENG-101", "ENG-102"])
        #expect(issues[0].id == "00000000-0000-4000-8000-000000000101" && issues[0].stateType == "unstarted" && issues[0].stateName == "TO DO")
        #expect(issues[1].stateType == "completed")
    }
}
