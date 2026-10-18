# MCP clients

RelayForge exposes a standard JSON-RPC MCP adapter. The initial implementation
supports **local stdio** only and advertises read-only diagnostic tools,
`relayforge_status`. The optional SSH pilot can query a small allowlist of remote devices using existing SSH credentials; no mutating operations are available. See `docs/ssh-pilot.md`.

The stdio pilot negotiates handshake-era MCP revisions
`2024-11-05`, `2025-03-26`, `2025-06-18`, and `2025-11-25`.
If the client proposes an unsupported revision, the server counter-offers
`2025-11-25` rather than echoing an unsupported version. The modern
`2026-07-28` stateless MCP lifecycle is **not implemented** yet. This
pilot does not yet enforce the full initialize-before-tools lifecycle.

## Codex and other local stdio clients

Build with `cargo build --release -p relayforge-mcp` and configure the client
to start `target/release/relayforge-mcp` as its stdio MCP server. Do not launch
through a wrapper that prints to stdout; stdout is reserved for JSON-RPC.

## ChatGPT and remote clients

ChatGPT requires a supported remote MCP transport and appropriate authentication.
**Do not point ChatGPT at this local stdio process.** HTTPS Streamable HTTP,
identity verification, enrollment, and permission enforcement are planned but
not implemented. Assistant Hub may eventually use the same MCP interface.

Client names are not credentials. No permission is implied by using Codex,
ChatGPT, or Assistant Hub.
