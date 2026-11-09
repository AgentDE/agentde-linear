import AgentDEKit
import AgentDEWidgets
import SwiftUI

/// Your open Linear issues, most urgent first; click one to open it in Linear.
struct LinearWidget: View {
    @Environment(LinearFeed.self) private var feed

    var body: some View {
        WidgetCard {
            if feed.signingIn {
                WidgetMessage(text: "Finish signing in to Linear in your browser.")
            } else if !feed.connected {
                WidgetMessage(text: feed.problem.map { $0 == .noKey ? nil : $0.message }.flatMap { $0 } ?? "Shows the Linear issues assigned to you.",
                              button: "Sign in with Linear") { feed.signIn() }
            } else if let problem = feed.problem, feed.issues.isEmpty {
                WidgetMessage(text: problem.message, button: "Try Again") { feed.loadIfNeeded(force: true) }
            } else if feed.issues.isEmpty {
                WidgetMessage(text: "No open issues assigned to you.")
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(feed.issues) { issue in LinearIssueRow(issue: issue) }
                    }
                    .padding(6)
                }
                .widgetListHeight(190)
            }
        }
        .onAppear { feed.loadIfNeeded() }
        .task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(180))
                if NSApp.isActive { feed.loadIfNeeded() }
            }
        }
        .contextMenu { Button("Refresh") { feed.loadIfNeeded(force: true) } }
    }
}

/// One issue: its state's colour, identifier and title. Also used for a workstream's tickets.
struct LinearIssueRow: View {
    let issue: LinearIssue
    var trailing: AnyView? = nil
    @Environment(\.theme) private var theme
    @State private var hovering = false

    var body: some View {
        Button { if let url = URL(string: issue.url) { NSWorkspace.shared.open(url) } } label: {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Circle().fill(Color(hexString: issue.stateColor)).frame(width: 7, height: 7)
                Text(issue.identifier).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(theme.muted)
                Text(issue.title).font(.system(size: 11.5)).foregroundStyle(hovering ? theme.text : theme.secondary).lineLimit(1)
                Spacer(minLength: 0)
                if let priority = LinearIssueRow.priorityMark(issue.priority) {
                    Text(priority).font(.system(size: 10, weight: .bold)).foregroundStyle(issue.priority == 1 ? Color(hex: 0xFF6B5E) : theme.muted)
                }
                if let trailing { trailing }
            }
            .padding(.horizontal, 4).padding(.vertical, 3)
            .background(RoundedRectangle(cornerRadius: 5).fill(hovering ? theme.selected : .clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help("\(issue.identifier) · \(issue.stateName) · open in Linear")
    }

    /// "!!!" urgent, "!!" high, "!" medium; nothing for low or none.
    static func priorityMark(_ priority: Int) -> String? {
        switch priority {
        case 1: "!!!"
        case 2: "!!"
        case 3: "!"
        default: nil
        }
    }
}

extension Color {
    /// "#f2c94c", or grey when it isn't a colour.
    init(hexString: String) {
        let digits = hexString.trimmingCharacters(in: CharacterSet(charactersIn: "#"))
        self.init(hex: digits.count == 6 ? UInt32(digits, radix: 16) ?? 0x95A2B3 : 0x95A2B3)
    }
}
