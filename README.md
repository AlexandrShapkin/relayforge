# RelayForge

A lightweight, self-hosted remote-device control plane written in Rust.

**Status: offline architecture prototype.** There is no active remote command executor, agent listener, authentication service, or working MCP endpoint yet.

## Universal MCP integration

RelayForge will implement **standard Model Context Protocol (MCP)** rather than a ChatGPT-specific API. The same coordinator will serve MCP clients including ChatGPT, Codex and Assistant Hub, subject to client capabilities and deployment configuration. Clients never gain privileges merely by identifying as a particular product.

- **ChatGPT:** remote HTTPS MCP transport, with compatible authentication.
- **Codex:** standard MCP transport supported by the installed Codex version.
- **Assistant Hub:** MCP client or direct versioned coordinator adapter; no dependency cycle.
- **Agents:** separate authenticated outbound connections; no public inbound device ports.

The MCP adapter is not a trusted policy authority. The coordinator and agent must independently enforce permissions. A client must be authenticated before any grant is evaluated.

## Rust workspace

- `relayforge-protocol`: versioned, transport-independent request contract.
- `relayforge-policy`: exact device/capability grants, deny by default.
- `relayforge-agent`: disabled placeholder, future outbound device agent.
- `relayforge-server`: disabled placeholder, future coordinator.
- `relayforge-mcp`: policy boundary, future standards-compliant MCP adapter.

Run `cargo test --workspace`. See `docs/security.md` and `docs/roadmap.md`.

No devices or existing services are modified by this prototype.
