import Foundation
import Testing
@testable import AgentDELinear

@Suite("Linear issues")
struct LinearFeedTests {
    @Test func linearIssuesInProgressAndUrgentComeFirst() {
        func issue(_ id: String, _ state: String, _ priority: Int) -> LinearIssue {
            LinearIssue(id: id, identifier: id, title: id, url: "", priority: priority, stateName: state, stateType: state, stateColor: "#fff")
        }
        let sorted = LinearFeed.sorted([issue("A", "backlog", 1), issue("B", "started", 4), issue("C", "started", 0),
                                        issue("D", "started", 1), issue("E", "unstarted", 2)])
        #expect(sorted.map(\.identifier) == ["D", "B", "C", "E", "A"])
    }
}
