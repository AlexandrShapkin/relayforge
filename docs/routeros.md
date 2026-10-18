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

## Verified access (ThinkPad)

Access and live MCP diagnostic operations `resource` and `identity` were
verified on hAP ax S (RouterOS 7.19.5). Its SSH service on port 2224
restricts source IPs to `192.168.88.115/32` and `192.168.88.116/32`.
The ThinkPad also has Ethernet `192.168.88.113`, which was rejected
before SSH key exchange. The ThinkPad's local `~/.ssh/config` entry for
`mikrotik` now uses `BindInterface wlp2s0`, selecting its authorized
Wi-Fi source address. This depends on Wi-Fi remaining connected and the
router's source-IP allowlist remaining current. The router's configuration
was not changed.

Before enabling configuration changes, implement authenticated actor policy,
backup, explicit confirmation and safe rollback. Do not expose this local
MCP process publicly.
