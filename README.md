<div align="center">

<img src="assets/relayforge-banner.svg" alt="RelayForge — Controlled infrastructure access" width="100%">

# RelayForge

**Controlled infrastructure access. Built in Rust.**

A security-first MCP bridge for personally operated Linux, MikroTik RouterOS, and Android devices.

[![CI](https://github.com/AlexandrShapkin/relayforge/actions/workflows/tests.yml/badge.svg)](https://github.com/AlexandrShapkin/relayforge/actions)
![Rust](https://img.shields.io/badge/Rust-1.85%2B-4A7CAB)
![License](https://img.shields.io/badge/License-Apache--2.0-5A9E7E)
![Status](https://img.shields.io/badge/Status-active%20development-C64B4B)

[Capabilities](#capabilities) · [Architecture](#architecture) · [Security](docs/security.md) · [Development](#development) · [Roadmap](docs/roadmap.md)

</div>

---

> [!IMPORTANT]
> **Active development — not a general-purpose remote administration tool.**
> RelayForge exposes deliberately narrow, allowlisted operations. It does not provide arbitrary shell access or unattended privileged control.

## Why RelayForge?

RelayForge connects an MCP client to a small, explicitly authorized set of infrastructure diagnostics and controlled operations. Rather than treating an AI assistant as an unrestricted administrator, it separates **observation**, **policy enforcement**, and **human approval**.

- **Deny by default.** Only explicitly supported actions are available.
- **Private connectivity.** A deployed outbound-only Secure MCP Tunnel connects an authorized ThinkPad to the MCP client.
- **Human-in-the-loop changes.** Supported mutations require exact, single-use local operator approval.
- **Auditable behavior.** Approval windows, bounded actions, and diagnostic evidence make changes inspectable.
- **Independent constraints.** Linux agents enforce their own allowlists rather than trusting the gateway alone.

## Capabilities

| Area | Available today | Outside the current scope |
| --- | --- | --- |
| **Linux** | Fleet diagnostics, user-service and timer status, scheduled-job evidence, bounded backup and file integrity checks | Arbitrary shell, unrestricted root service management |
| **MikroTik RouterOS** | Fixed read-only network and management posture diagnostics over authenticated SSH | Router configuration changes and automatic rollback |
| **Android** | Discovery and bounded health checks for locally authorized ADB devices | Pairing, screenshots, app or settings manipulation |
| **Change control** | Allowlisted, exact, expiring, single-use operator-approved actions with audit | Autonomous unrestricted administration |
| **Development** | Rust workspace, GitHub Actions, documented RDC-independent workflow | Claims of production-wide general availability |

## Architecture

```text
                MCP client
                    |
           Secure MCP Tunnel
           (outbound-only)
                    |
            relayforge-mcp
             /     |      \
      policy    coordinator  adapters
         |                    |
   bounded operations    SSH / local ADB
         |                    |
    Linux agents       RouterOS / Android
```

The gateway, policy layer, and agents are separate components. Remote actions remain constrained by the destination-specific implementation and authorization model.

## Rust workspace

| Crate | Responsibility |
| --- | --- |
| `relayforge-protocol` | Versioned request and response contracts |
| `relayforge-policy` | Deny-by-default capability policy |
| `relayforge-agent` | Independently bounded Linux diagnostics |
| `relayforge-server` | Limited coordinator and session primitives |
| `relayforge-mcp` | MCP gateway and device integrations |

## Development

Requires **Rust 1.85+**. From the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked -p relayforge-agent -p relayforge-mcp
```

For local read-only MCP testing:

```bash
target/release/relayforge-mcp --readonly-stdio
```

Standard output must contain JSON-RPC only. The Secure MCP Tunnel launcher must remain restricted to `--readonly-stdio`; never expose the local change-control pilot as a remote unrestricted gateway.

The canonical branch is `main`. Changes are developed in short-lived branches and reviewed through pull requests. See the [RDC-independent development playbook](docs/development-without-rdc.md).

## Documentation

- [Security model](docs/security.md)
- [Secure MCP Tunnel and approvals](docs/tunnel-readonly.md)
- [Fleet monitoring](docs/fleet-health.md)
- [RouterOS integration](docs/routeros.md)
- [Android integration](docs/android.md)
- [MCP client setup](docs/mcp-clients.md)
- [Development without RDC](docs/development-without-rdc.md)
- [Roadmap](docs/roadmap.md)

## Security and project status

RelayForge is operated on explicitly authorized devices. Never commit credentials, SSH keys, ADB authorization material, production settings, private logs, or backups. Mock tests and CI do not replace real-device validation or deployment review.

The project is under active development; the README describes implemented functionality, **not** a promise of general availability.

## License

Apache-2.0. See the license information in the Rust workspace.
