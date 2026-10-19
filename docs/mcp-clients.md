# MCP client integration

RelayForge provides a JSON-RPC stdio MCP adapter with restricted
diagnostics and narrowly scoped human-approved pilot changes.

The adapter supports handshake-era MCP versions `2024-11-05`,
`2025-03-26`, `2025-06-18`, and `2025-11-25`. The newer
`2026-07-28` stateless lifecycle is not implemented. The initial
initialize-before-tool lifecycle is not yet fully enforced. Do not
claim complete protocol conformance.

## Local stdio

```sh
cargo build --release --locked -p relayforge-mcp
target/release/relayforge-mcp --readonly-stdio
```

Standard output is reserved for protocol frames. Never connect a
remote gateway to the unrestricted local development entrypoint.

## ChatGPT private Secure MCP Tunnel

The tested ChatGPT transport is an **outbound-only** Secure MCP Tunnel
operated by an authorized ThinkPad user service. Its launcher invokes
`--readonly-stdio` and exposes allowlisted Linux, RouterOS and Android
read-only diagnostics. It can prepare tightly scoped changes for a
separate **interactive local operator approval**; there is no remote
approval tool.

See [tunnel deployment](tunnel-readonly.md) and
[onboarding](openai-secure-tunnel.md). Check both that the user service
is active and that an authenticated control-plane poll succeeded
recently. After modifying MCP tools, ChatGPT plugin discovery may
need refreshing.

## Other clients

Codex and Assistant Hub might use standard MCP transport with suitable
configuration but have not received the same end-to-end qualification
as the private ChatGPT tunnel. Client names convey no permission.
