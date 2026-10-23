# Local-only Streamable HTTP MCP pilot

This is an authenticated **loopback-only** MCP endpoint to exercise
Streamable HTTP with a real read-only RelayForge agent. It is NOT yet
a ChatGPT remote connector or a production internet-facing resource server.

The binary binds exclusively to 127.0.0.1 and defaults to port 8765.
A 256-bit random bearer credential MUST be read from an absolute path
to a private regular file (mode 0600 or 0400); the program never logs it.
The endpoint requires a valid Authorization Bearer header, valid local Host,
both application/json and text/event-stream in Accept, application/json
Content-Type, and a request body <= 64 KiB. Browser Origin headers are rejected.
Unknown protocol revisions are rejected; SSE GET is not implemented.
Notifications receive 202; synchronous JSON-RPC requests return JSON.

To test locally:
```sh
mkdir -p ~/.config/relayforge
chmod 700 ~/.config/relayforge
umask 077
openssl rand -hex 32 > ~/.config/relayforge/http-token
RELAYFORGE_HTTP_TOKEN_FILE="$HOME/.config/relayforge/http-token" relayforge-mcp --http
```

From another terminal, read the token into a private shell variable and send
an initialize POST to http://127.0.0.1:8765/mcp. Never paste the token
into logs, issue trackers, commands shared with other people or GitHub.

### Not ready for internet exposure

No OAuth 2.1 authorization server, resource-server JWT validation, access
revocation, issuer/audience/scope enforcement or external HTTPS ingress
is configured. A static local bearer token does not substitute for OAuth.
Never use an unauthenticated reverse proxy or bind 0.0.0.0; use local
tunnelling for tests only. Public ChatGPT access is BLOCKED pending
OAuth 2.1 integration, validated TLS, operational access policy, and
adversarial testing.

## Persistent local service (ThinkPad pilot)

The service template is tracked in
`deploy/systemd/relayforge-mcp-http.service`. It is installed under
`~/.config/systemd/user/`; `systemctl --user enable --now
relayforge-mcp-http.service` starts it at boot provided systemd user
lingering is enabled. No root service, public listener or inbound firewall
rule is created. On ThinkPad it has been tested with systemd and the
local authenticated HTTP MCP call.

API 9 artifact read/list requires a durable audit append before accessing a
report. The template retains `ProtectHome=read-only` and permits writes only
to `%h/.local/state/relayforge/workstation-dev-audit.jsonl`. Before an independently
authorized installation, that file must already exist as an owner-held,
single-link regular file, mode 0600, in the private 0700 RelayForge state
directory. A missing file prevents unit startup; an unavailable, insecure or
oversized audit fails artifact operations closed. The exception does not permit
creating sibling files or writing reports, configuration or runtime artifacts.

Issue #77 user-scope verification found that systemd 262 maps only UID 1000
(`1000 1000 1`): host-root-owned `/home` appears as UID 65534. The unchanged
artifact `home_dir()` rejects it at `m.uid() != 0 && m.uid() != uid()?`.
The configuration-only correction supports **only `/home/<username>` homes**:

```
BindReadOnlyPaths=%h/.local/share/relayforge/http-home:/home %h:%h
```

Before any separately authorized installation, the owner must prepare the private
0700 scaffold and its single empty 0700 `<username>` directory. All components
must be owner-controlled, non-symlink and not writable by group/others. The
prepared package checks these prerequisites without creating live files. Systemd
mounts the parent first, then restores the actual home at its original path;
both mounts are read-only. The scaffold hides unrelated homes. The unchanged
Rust code still pins and validates actual HOME, config, roots and report files;
UID 65534 receives no trust. The only writable home exception is the existing
audit file. Missing mandatory mount sources fail startup. The service cannot
create its missing audit file; a separately prepared 0600 file permits append
and fsync. No directory-wide writable exception is used.

This assumes a trusted owner: a hostile process with the same UID can replace
owner-controlled configuration and mount sources outside the service. The
preflight is not an atomic defense against a malicious same-UID operator.
Symlink traversal inside artifact lookups remains descriptor-pinned and denied.
Other home layouts require separate review; do not generalize this template.

`scripts/test_http_audit_isolation.py BINARY` runs authenticated HTTP acceptance
in disposable systemd **user** services, including the original failure,
audit-only failure, corrected read/list, actual unmapped ownership denials,
symlink/hardlink/mode denials, missing-audit creation failure and fail-closed
oversized audit. It preserves installed services and binary identities.
