# Restrained service-control proof

`relayforge_agent_probe_restart` is a deliberately narrow pilot action:
it may restart ONLY `relayforge-probe.service` on `ru0`. This is a
systemd *user* oneshot unit executing /usr/bin/true; it has no listener,
no application side effects, and never gains root privileges.

The MCP caller cannot choose an arbitrary command, unit, or host.
Both MCP and the Rust agent independently reject unsupported operations.
Any control of real infrastructure services (nginx, SSH, RDC, Docker,
Assistant Hub, networking) remains disabled until individual actor
authentication, scoped grants and explicit recovery paths are implemented.
