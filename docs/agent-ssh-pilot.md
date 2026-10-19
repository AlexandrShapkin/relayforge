# Read-only Rust agent pilot via SSH

The agent provides a single JSON request/response over stdio. It has no
network listener, no persistent process and no privilege elevation. MCP
invokes it as the existing authenticated SSH user on the allowlisted VPS
hosts, via `relayforge_agent_query`. Host keys are checked with OpenSSH.

Remote install path:
`/home/shapkin_as/.local/libexec/relayforge-pilot/relayforge-agent`

Request: `{"version":1,"operation":"device.status"}`
Response: `{"ok":true,"data":{"hostname":"...",...}}`

Request: `{"version":1,"operation":"service.status","unit":"ssh.service"}`
Response: `{"ok":true,"data":{"Id":"ssh.service","ActiveState":"active",...}}`

Additional fixed read-only operations:
- `service.list`: up to 64 running/failed services with names and states.
- `process.top`: up to 20 processes by resident RAM, with PID and process
  name only. No argv, environment, secrets, shell commands or credentials.

The agent validates both operation and service name independently from
MCP. It permits only device status, service/process inventories and selected
fixed systemd properties.
Unsupported, malformed, oversized and mutating requests are denied.
No arbitrary command execution, file writes or listener is enabled. These operations were deployed and exercised on `ru0` and `srv0` with a read-only MCP smoke test on `ru1` and `srv0`.

**Trust boundary:** SSH authentication identifies the Unix account, not
the requesting MCP actor. The local stdio MCP process must only be
exposed to trusted, locally authorized users. Multi-actor authorization,
outbound agent transport and credential rotation are still future work.
Do not expose the SSH-backed pilot publicly or treat it as full remote
MCP support.
