# RelayForge private tunnel bootstrap profile

Run a separate MCP process in `--readonly-stdio` mode for remote ChatGPT.
This mode permits fixed diagnostics for Linux hosts, MikroTik and already
authorized Android devices. It additionally supports preparing a strictly
limited change, tracking its status and audit history, and committing it **only after a
distinct interactive ThinkPad terminal approval**. Original unrestricted
file-write and probe-restart MCP tools remain denied by name even if a
remote caller manually invokes them.

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

## Approved mutation pilot

A distinct remote `relayforge_file_inspect` tool allows `list` and
`read` against existing Rust-agent public OS metadata allowlists and the
private scratch directory. It never accepts a write operation or arbitrary
filesystem paths, and the agent checks the allowlist again.

The only remotely available change actions are `sandbox.create` on
`ru0`, `ru1`, or `srv0` (flat file with .txt, .md, .json extension,
up to 2048 UTF-8 bytes in the agent's throwaway private scratch
directory), and `probe.restart` on `ru0` (an inert systemd user
oneshot unit). The restricted tunnel publishes four new tools:

- `relayforge_change_prepare`: validates the entire action, stores its
  exact arguments in a private 0600 approval record, and returns the
  random 128-bit approval ID and expiry. Nothing is executed.
- `relayforge_change_status`: reports pending/approved/finished status
  without revealing file content.
- `relayforge_change_commit`: claims an approved request exactly once,
  logs the attempted execution and result, then calls the agent.
- `relayforge_change_audit`: reads up to 20 recent audit events, without
  displaying proposed file contents.

Approval is available through an interactive ThinkPad OS-user terminal
(not through RelayForge MCP tools):
```sh
~/Projects/relayforge/target/release/relayforge-mcp --approve-change APPROVAL_ID
```
Review target host, exact operation and JSON-escaped file content before
typing the displayed `APPROVE APPROVAL_ID` phrase. Every grant expires
after 300 seconds and cannot authorize a different action or device.
Expiry also releases queued capacity for subsequent requests. At most
24 awaiting grants are retained; completed receipts are retained for
seven days. Audit events are persisted locally as JSONL under
`~/.local/state/relayforge/audit.jsonl` (0600), capped at 16 MiB;
when recording fails, execution is denied rather than unlogged.

An interactive terminal can also be created by other trusted remote
desktop tools under the same Unix account; this is not cryptographic
proof of human presence. The assistant must never approve its own requests
using RDC, SSH or any other terminal connector.

This **does not establish a verified per-actor ChatGPT identity**. An
authorized request is bound to an exact operation and an OS-local human
confirmation, not to the identity of the ChatGPT message author.
The audit file is a local same-user log, not a tamper-proof audit trail.
The full `~/.local/state/relayforge` subtree is private (0700), and
the tunnel systemd unit can write only that state directory and its
own private runtime directory.

Never authorize changes to SSH, networking, RDC, the RelayForge tunnel,
firewall, real systemd services, router configuration, or arbitrary paths
under this pilot. These require separately authenticated actors, a
device-specific recovery/rollback mechanism, and reviewed least-privilege
service allowlists.

## Long-poll reliability on ThinkPad (Happ/Xray route)

ThinkPad uses a local outbound Happ/Xray network route. During the October
18 pilot the tunnel-client's default 30-second control-plane long polls
repeatedly hit the HTTP/context timeout while short HTTPS requests to
api.openai.com succeeded. The systemd service now uses a 12-second
control-plane poll timeout, 12-second initial poll timeout and 10-second
deadline guardrail. In a 50-second smoke test this yielded three completed
control-plane poll cycles without new timeouts. This is preliminary, not a
guarantee of long-term stability.

The tunnel-client `health --require-control-plane-poll` check proves **at
least one historical successful poll since process start**; it does not
guarantee freshness. Compare the `control_plane_poll.value` timestamp to
the current Unix time, and inspect `commands_poll_errors_total` before
declaring the connection currently healthy. A running systemd process
alone is also insufficient evidence of remote reachability.
