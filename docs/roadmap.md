# RelayForge roadmap

RelayForge is a working restricted bridge, **not** a completed
universal remote administration product.

## Implemented and tested

- Rust workspace, versioned protocol, deny-by-default policy and CI.
- Authenticated SSH-backed, read-only Linux diagnostics and fleet health.
- Private outbound Secure MCP Tunnel with restricted stdio gateway.
- Audited, expiry-bound, exact one-time approvals exercised on an
  innocuous Linux pilot. Approvals require a local human terminal.
- Fixed RouterOS diagnostics and source-limited management-service
  posture checks; no configuration writes.
- Authorized ADB diagnostics and mock-tested Android health.
- Bounded backup/archive and calendar/monitoring artifact evidence.

## Outstanding work

1. Validate Android health parsing against physically authorized devices.
2. Add per-source calendar sync receipts and investigate the VPN health
   probe failure; local database integrity does not guarantee sync.
3. Exercise tunnel reconnect, identity revocation and recovery under
   realistic failure conditions.
4. Design RouterOS writes with tested independent access, local rollback
   and the existing operator approval boundary **before** any changes.
5. Define Android mutation capabilities subject to device-side consent,
   operating system permissions and auditability.
6. Run release security review, update/rollback rehearsal, hardware
   verification, no-secret checks and a full deployment checklist.

No internet-facing executor, silent pairing or unrestricted remote
shell is planned for this stage.
