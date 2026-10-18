# RelayForge private tunnel bootstrap profile

Run a separate MCP process in `--readonly-stdio` mode for remote ChatGPT.
This mode permits only fixed diagnostics for Linux hosts, MikroTik and
already-authorized Android devices, and rejects file writes and service
restarts both during tool discovery and actual invocation.

The separate private tunnel command is:
`/home/user/.local/libexec/relayforge/relayforge-tunnel-mcp`
It invokes the release binary with `--readonly-stdio`. Do not repoint
the tunnel to the unrestricted default stdio binary.

The tunnel-client profile `relayforge-local` is configured for the user's
tunnel, with credential reference pointing to:
`/home/user/.config/relayforge/tunnel/runtime-key`
The credential must be created locally, mode 0600, and never committed or
sent to chat. The user needs a runtime OpenAI Platform key with
Tunnels Read + Use for the correct organization.

The tunnel is **not ready** until the key exists, `doctor --explain`
reports authorization and MCP success, the managed runtime is healthy
and the ChatGPT private plugin exposes a real diagnostic tool.

## Installation on ThinkPad (credentials remain local)

The profile is stored in `~/.config/tunnel-client/relayforge-local.yaml`
(mode 0600). Its tunnel ID is stored only in the local profile (not in Git).
The profile references `file:/home/user/.config/relayforge/tunnel/runtime-key`,
which **must not** be checked into Git or sent to ChatGPT.

The user service unit `deploy/systemd/relayforge-tunnel.service` is
installed on ThinkPad but deliberately **not enabled** until credentials
pass `tunnel-client doctor --profile relayforge-local --explain`.
It uses an outbound tunnel and binds only a loopback health endpoint.
`ProtectHome=read-only` and `NoNewPrivileges` remain enabled.

To activate, create a restricted runtime API key in
https://platform.openai.com/settings/organization/api-keys
with **Tunnels Read + Use** in the organization that owns this tunnel,
then run the interactive ThinkPad helper:
`~/.local/libexec/relayforge/relayforge-tunnel-activate`.
It prompts for the key without echoing it, writes mode 0600, runs doctor,
then enables the user service only on success.

After activation, inspect:
`systemctl --user status relayforge-tunnel.service`,
`journalctl --user -u relayforge-tunnel.service -n 30 --no-pager`
(without printing bearer credentials),
and the local `/readyz` URL written into `%t/relayforge-tunnel/health.url`. The systemd unit creates that private
runtime directory and grants write access only there while preserving
`ProtectHome=read-only`. The user service has `RuntimeDirectory=relayforge-tunnel`
(mode 0700) and only that runtime directory is writable for the health
URL file. Startup checks require `tunnel-client health --require-control-plane-poll`
to succeed; `systemctl active` alone does not imply remote connectivity.
Finally create or connect the **private** ChatGPT MCP plugin for this tunnel
and verify a real `relayforge_agent_query` call.
