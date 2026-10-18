# RouterOS / MikroTik hAP ax S pilot

RelayForge exposes `relayforge_routeros_diagnostic` via local stdio MCP.
It uses the preconfigured `mikrotik` SSH alias (RouterOS SSH, not RouterOS
API) and existing SSH host-key verification and credentials.

The only accepted argument is `check`: resource, identity, interfaces,
addresses, routes, dhcp_leases, or wifi. All commands are fixed read-only
RouterOS commands. No arbitrary scripts or configuration mutations.

The transport has an 8-second deadline and 16-KiB output limit. The local
SSH identity must be granted the minimum necessary read-only RouterOS rights.
The tool reports a failure when the router is unavailable; it does not try
alternative hosts, ports or credentials.

Note: initial reachability test from ThinkPad to its existing SSH alias
failed with connection reset. This adapter is implemented and tested for
argument validation, but live RouterOS diagnostic success is NOT yet verified.

Before enabling configuration changes, implement authenticated actor policy,
backup, explicit confirmation and safe rollback. Do not expose this local
MCP process publicly.
