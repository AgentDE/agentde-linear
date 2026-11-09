# agentde-linear

An AgentDE extension for Linear.

| Adds | What |
|---|---|
| Ticket provider | Workstream tickets from Linear (`ENG-123`, or a linear.app issue link) show their state, priority and title, looked up at most every 5 minutes each; ⊕ in the panel's Tickets section lists your open issues to link |
| Linear widget | Your open assigned issues, in progress first, then by priority; click one to open it. Right-click → Refresh (needs `agentde-widgets`) |

## Include it

It's in AgentDE's default `extensions.json`, so building AgentDE clones it (and `agentde-widgets`) beside `agentde/`:

```json
{ "package": "../agentde-linear", "product": "AgentDELinear", "create": "LinearExtension()" }
```

## Settings

Settings → Extensions → Linear:

| Setting | What |
|---|---|
| Sign in with Linear | Opens Linear's approve page in your browser; uses whichever Linear account the browser is signed in to. **Sign Out** to switch |
| Use an API key instead | A personal API key (Linear → Settings → Security & access → Personal API keys) |

Either is kept in your login Keychain, under `<bundle id>.linear-oauth` or `<bundle id>.linear`.

## License

MIT; see [LICENSE](LICENSE).
