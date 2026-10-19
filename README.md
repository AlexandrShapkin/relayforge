# RelayForge

RelayForge is a Rust-based, permission-limited MCP bridge for
personally operated Linux, MikroTik RouterOS and Android devices.

**Current status:** deployed read-only diagnostics and narrowly scoped,
human-approved Linux pilot. This is **not** a general remote device
administration system.

The tested deployment runs a private **outbound-only Secure MCP Tunnel**
on an authorized ThinkPad. The tunnel invokes a restricted MCP process.
Linux agents on `ru0` and `srv0` check host and user-service
status under independent allowlists. MikroTik uses existing authenticated
SSH for fixed read-only RouterOS commands. Android requires an already
physically authorized local ADB connection.

## Available capabilities

| Platform | Implemented | Not implemented |
|---|---|---|
| Linux | Fleet health, user services/timers, scheduled-job evidence, bounded file and backup integrity checks | Arbitrary shell, root service control, unattended device recovery |
| RouterOS | PPPoE, route, DHCP, Wi-Fi, firewall/NAT counts and management service posture | Configuration changes or automatic rollback |
| Android | Authorized ADB discovery, bounded read-only health probes | Pairing, app operations, screenshots, settings or file changes |
| Change control | Allowlisted, exact, single-use approved actions with audit and expiries | General autonomous system administration |

A human operator approves permitted changes at a **local interactive
ThinkPad terminal**, after reviewing the exact operation. An AI must
not approve changes by SSH, remote desktop, scripts or MCP tools.

See [security](docs/security.md),
[tunnel and change approval](docs/tunnel-readonly.md),
[RouterOS](docs/routeros.md),
[Android](docs/android.md), and
[fleet monitoring](docs/fleet-health.md).

## Development

The canonical development branch is `main`. Use short-lived branches
from `main` and pull requests. The [RDC-independent development playbook](docs/development-without-rdc.md)
describes how to edit, test, build and review RelayForge entirely through
the connected GitHub integration, without ThinkPad or Remote Desktop Commander.
Run all checks before merging:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p relayforge-agent -p relayforge-mcp
```

Use `target/release/relayforge-mcp --readonly-stdio` for local read-only
MCP testing. Standard output is JSON-RPC protocol only; launch wrappers
must not print status banners there. Keep the Secure MCP Tunnel launcher
restricted to `--readonly-stdio`; do not use the unrestricted local pilot
as a remote gateway.

## Rust workspace

- `relayforge-protocol`: versioned request contracts.
- `relayforge-policy`: deny-by-default capability policy.
- `relayforge-agent`: independently bounded Rust diagnostics.
- `relayforge-server`: limited coordinator/session primitives.
- `relayforge-mcp`: MCP gateway and RouterOS/Android integrations.

GitHub Actions tests pull requests and pushes. Passing mock tests does
not replace real-device testing or an independent deployment review.
Do not commit credentials, SSH keys, ADB authorizations, private data,
archives or production runtime settings.

See [MCP clients](docs/mcp-clients.md) and the
[remaining roadmap](docs/roadmap.md).
