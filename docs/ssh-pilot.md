# SSH-backed read-only MCP pilot

The `relayforge_diagnostic` tool is a temporary integration pilot for local
Codex and other trusted stdio MCP clients. It uses the operating system's
existing SSH identity and host-key verification. It does **not** implement
RelayForge agent-to-coordinator transport.

Allowed hosts: `ru0`, `ru1`, `srv0` (resolved by existing SSH config).
Allowed diagnostics: `identity`, `hostname`, `uptime`, `memory`,
`disk`, `kernel`. No caller-supplied shell commands are accepted.

Requires OpenSSH and GNU `timeout`. Requests have an 8-second deadline and
16-KiB output cap. SSH authentication is noninteractive and host keys must
already be trusted. Do not expose the stdio process as an unauthenticated
network service.

Run locally with `cargo run --release -p relayforge-mcp`. Configure Codex
with `codex mcp add relayforge-pilot -- /absolute/path/to/relayforge-mcp`.

The local MCP client's process identity determines its SSH privileges.
Therefore, **do not give this bridge to untrusted MCP clients**. Future
versions must authenticate actors, enforce per-device policy and use an
outbound agent connection before adding mutating capabilities.
