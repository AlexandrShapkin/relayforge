# Security principles

RelayForge is a high-risk control plane. A compromised service could affect every connected device.

- Explicit, device-scoped least-privilege grants; deny by default.
- Strong mutual device identity, rotation, revocation, and replay resistance before network access.
- User-to-device authorization independently verified at the agent, never only in an MCP tool description.
- No arbitrary remote shell in the first networked release. No root daemon or implicit sudo.
- Destructive operations require separate, contextual confirmation.
- Structured redacted audit logs, bounded output, timeouts, per-device rate limits.
- Prevent path traversal and symlink races using OS-level file descriptor APIs; string path checks are insufficient.
- No credentials, hosts, tokens, private keys, or deployment secrets in the public repository.
- No internet-facing service until authenticated transport and adversarial testing are complete.
