# RouterOS / MikroTik hAP ax S pilot

RelayForge exposes `relayforge_routeros_diagnostic` via local stdio MCP.
It uses the preconfigured `mikrotik` SSH alias (RouterOS SSH, not RouterOS
API) and existing SSH host-key verification and credentials.

The only accepted argument is `check`: resource, identity, interfaces,
addresses, routes, dhcp_leases, or wifi. All commands are fixed read-only
RouterOS commands. No arbitrary scripts or configuration mutations.

The transport has an 8-second deadline and 16-KiB output limit. The local
SSH identity must be granted the minimum necessary read-only RouterOS rights.
The tool first uses SSH alias `mikrotik`, which follows OS routing
(Ethernet is preferred when connected). If it fails, it retries the same
fixed read-only command through `mikrotik-wifi`, which explicitly binds the
Wi-Fi interface. Both aliases resolve to the same router and use the same
SSH key, host-key checking and permissions. Each attempt has its own
8-second timeout, so failover can take up to 16 seconds.

## Verified access (ThinkPad)

Access and live MCP diagnostic operations `resource` and `identity` were
verified on hAP ax S (RouterOS 7.19.5). Its SSH service on port 2224
restricts source IPs to `192.168.88.115/32` and `192.168.88.116/32`.
The ThinkPad also has Ethernet `192.168.88.113`, which was rejected
before SSH key exchange. The router has static DHCP reservations for ThinkPad Ethernet
`192.168.88.113` and Wi-Fi `192.168.88.115`. Both source IPs have
been added to the RouterOS SSH service and `ai-ops` user allowlists.
The local `mikrotik` alias follows the normal route (Ethernet preferred);
`mikrotik-wifi` uses `BindInterface wlp2s0`. Live tests confirmed
both paths without disabling network interfaces. The SSH service on
port 2224 remains LAN-restricted.

Before enabling configuration changes, implement authenticated actor policy,
backup, explicit confirmation and safe rollback. Do not expose this local
MCP process publicly.
