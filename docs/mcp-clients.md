# MCP clients

RelayForge exposes a standard JSON-RPC MCP adapter. The initial implementation
supports **local stdio** only and advertises a single read-only diagnostic tool,
`relayforge_status`. No devices can be controlled by this version.

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
