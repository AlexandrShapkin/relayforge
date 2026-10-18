# RelayForge

Self-hosted, policy-governed remote device management for MCP clients.

**Status:** Early prototype. No remotely reachable command executor or MCP endpoint is enabled.

## Architecture

- **Agent:** connects outbound to a trusted coordinator and executes narrowly authorized operations.
- **Coordinator:** authenticates agents and users, applies per-device policy, and records auditable requests.
- **MCP adapter:** exposes approved coordinator actions to MCP clients; it must never bypass policy.

Start with an offline, deterministic command-authorization core. Authentication, transport, process execution, device enrollment, and deployments will be built and reviewed separately.

## Development

Run `PYTHONPATH=src python3 -m unittest discover -s tests -v`.

See [security principles](docs/security.md) and [roadmap](docs/roadmap.md).
