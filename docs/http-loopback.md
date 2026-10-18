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
