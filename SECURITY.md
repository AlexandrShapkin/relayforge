# Security policy

RelayForge is under active development, not a general-purpose remote administration system.

## Vulnerability reporting

Do not disclose vulnerabilities, exploits, credentials, or private infrastructure details in public issues. Use GitHub private vulnerability reporting if enabled, or contact the repository maintainer privately. No response-time SLA is promised.

Include affected revision, impact, and sanitized reproduction steps. Only test devices you own or are explicitly authorized to assess.

## Security boundaries

Operations are deny-by-default, device-specific and bounded. The deployed Secure MCP Tunnel is outbound-only and read-only. Supported changes require exact, local, interactive human approval. See [security architecture](docs/security.md).
