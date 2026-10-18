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

## Extended live diagnostics and posture snapshot

The read-only RouterOS diagnostic tool additionally accepts:
dhcp_servers, bridge_ports, firewall_filter_count, firewall_nat_count,
wifi_clients_count, and dhcp_leases_count. All of these map to constant
RouterOS print commands; the MCP caller cannot choose a command or host.

New MCP tool: relayforge_routeros_health (no arguments).

It sends one fixed, delimiter-marked, read-only RouterOS script over
the existing strict-key SSH connection, falling back from Ethernet to
Wi-Fi only when required. The fixed script reads resource, interfaces,
routes, DHCP server status, wireless radios, firewall/NAT rule counts,
wireless association count, lease count and IP management service
settings. No configuration is changed and no new listener or privileged
SSH identity is required.

Results are filtered before leaving the ThinkPad: no MAC addresses,
DHCP client names/IDs, IP addresses, SSIDs, wireless secrets, full
firewall rules, network credentials or complete export are returned.

The summary distinguishes operational faults (inactive PPPoE, missing
main-table active default route or inactive DHCP server) from
management-service configuration advisories. RouterOS supports an
address= allowlist on individual IP services. A blank address= (including
`address=""`) or an allowlist containing an IPv4 or IPv6 `/0` entry for an
enabled management service is reported as source_unrestricted with status
attention. Valid host addresses and narrower subnets are source_restricted;
missing or malformed restrictions fail the snapshot as unknown. Dynamic
connection rows (dynamic/connection flags or local=/remote= endpoints) and
disabled services do not contribute to the configured service scope.
**This does not prove internet exposure:**
the RouterOS input firewall may independently block all external
connections. Do not change service access restrictions remotely without
a verified alternate management path, a local rollback mechanism and a
separate operator-approved change.

The diagnostic provides a snapshot, not a monitoring SLA. PPPoE may be
running while an upstream network is unusable; configured NAT/filter
rule counts do not validate effective firewall policy. Disabled
interfaces may be intentionally unused.

### First verified result, RouterOS 7.19.5 hAP ax S

PPPoE running, main default route active, two Wi-Fi radios running,
three associated Wi-Fi clients, five DHCP leases, one DHCP server,
11 filter rules and eight NAT rules. The FTP, WinBox and API services
have no service-level source restriction; SSH has an allowlist. This is
a configuration advisory, not an assertion of WAN reachability.

Configuration changes remain disabled at this stage.
