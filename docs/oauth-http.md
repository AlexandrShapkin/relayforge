# Opt-in OAuth HTTP resource (Issue #114)

Source preparation only: no services, existing profiles, keys or packages are
changed by this procedure until a separately authorized operator performs it.
The current stdio tunnel, `relayforge-tunnel setup`, static-token `--http` mode,
and Issue #89 recovery evidence remain supported and unchanged. This is a
resource server, not an authorization server. It listens only on **127.0.0.1**;
OAuth does not authorize a public listener. Existing tool/agent grants still apply.

## Provider: an existing Keycloak realm

Use a provisioned, browser-reachable HTTPS Keycloak realm. Its OIDC discovery
is `{issuer}/.well-known/openid-configuration`; its exact `issuer` and same-origin
`jwks_uri` must match the configured realm. Configure TLS with a trusted CA.
The backend neither follows metadata redirects nor sends credentials to the IdP.
The realm owns browser login, consent, PKCE, registration, token refresh and MFA.

Provision a dedicated OpenID Connect client for the private ChatGPT connector:

- Enable authorization-code flow and require **PKCE S256**. Disable implicit,
  password/direct-access and service-account grants. Use a statically registered
  client and the exact redirect URI displayed by ChatGPT; do not use wildcards.
  Configure the client ID and, for a confidential client, its secret directly in
  ChatGPT and Keycloak through their native secure settings. RelayForge needs
  neither value. DCR/CIMD is unnecessary for this static registration path.
- Define the `mcp:read` client scope, include it in the access-token `scope` claim,
  and grant it only to the owner. Add a hardcoded audience protocol mapper whose
  **Included Custom Audience** is the canonical HTTPS MCP URL shown for the
  selected tunnel. Enable it for access tokens only. Check the actual `aud`:
  Keycloak deployments may need this explicit mapper when processing OAuth
  `resource` indicators. Do not use a client ID or the loopback URL as audience.
- Record the owner's immutable realm user ID (`sub`) in the resource config.
  Other realm users are refused even if issued the same scope. Use short access
  token lifetimes. The selected profile accepts signed **RS256** JWT access
  tokens with Keycloak's `typ: Bearer` claim; ID/refresh tokens and opaque tokens
  are unsupported. The provider must return access tokens with the exact issuer,
  resource audience, subject and scope. An audience array may contain the resource.

Use `resource.example.json` from `/usr/share/doc/relayforge/` as the shape for
`~/.config/relayforge/oauth-tunnel/resource.json`; replace every placeholder.
`resource` is the canonical client-facing HTTPS resource, including the complete
tunnel ID and any deployment-specific base path, **not** `http://127.0.0.1:8766/mcp`.
The internal metadata advertises the loopback MCP resource so tunnel-client
registers the local forwarding target. Tunnel-service rewrites that resource
and discovery URLs for the external client; its final advertised resource
must equal the configured audience. A mismatch blocks live acceptance.

## Native tunnel configuration and credentials

The optional, separately named `relayforge-mcp-oauth.service` and
`relayforge-tunnel-http.service` are packaged **disabled**. They use port 8766,
leaving the static-token pilot's port 8765 alone. They never stop or conflict
with `relayforge-tunnel.service`. For acceptance, select a separate test tunnel:
never poll the working tunnel concurrently with a second stdio/HTTP profile.
No installation, daemon-reload, start, enable or cutover is part of source work.

After separate installation/setup authority, an operator can use the official
client's initializer in a new private directory, without the custom setup helper:

```sh
umask 077
mkdir -p ~/.config/relayforge/oauth-tunnel
# Inspect native help for the installed independently verified version first.
tunnel-client help quickstart
tunnel-client init --sample sample_mcp_with_dcr \
  --profile-dir ~/.config/relayforge/oauth-tunnel --profile relayforge-oauth \
  --tunnel-id YOUR_SEPARATE_TEST_TUNNEL_ID \
  --mcp-server-url http://127.0.0.1:8766/mcp
```

Edit that new `relayforge-oauth.yaml` using the minimal
`/usr/share/doc/relayforge/tunnel.example.json` shape (JSON is valid YAML).
Set only the intended tunnel ID, one `main` HTTP binding, the **exact HTTPS IdP
origin** in `mcp.oauth_trusted_origins`, ephemeral loopback health listener,
and `harpoon.allow_plaintext_http: true` for this loopback hop. Keep other
channels/targets absent, raw HTTP logging off and runtime/discovery
`extra_headers.Authorization` absent. The client forwards each connector's
OAuth Authorization header automatically; never substitute a static OAuth token
or the OpenAI runtime key in an MCP header. These fields/flags are verified
against the packaged official tunnel-client **v0.0.18** documentation.

There are **two separate credentials**:

1. The connector obtains the owner's short-lived OAuth access token from Keycloak
   after browser consent. It travels to RelayForge as a bearer header and is
   validated on every protected request. RelayForge stores no access/refresh token.
2. The tunnel daemon still requires an **OpenAI Platform runtime API key** with
   only **Tunnels Read + Use**, for outbound polling and posting responses to the
   OpenAI control plane. OAuth does not replace it. An admin/Manage key is
   inappropriate. Eliminating this runtime key requires a separately approved
   transport change, outside this task.

Provision a fresh runtime key locally with native secure input, never paste it
into the custom helper, command arguments, GitHub or chat. For example, with
`umask 077` still set and the destination confirmed absent:

```sh
# Native hidden input; write only to the NEW operator-selected path.
(set -C; systemd-ask-password 'OpenAI tunnel runtime key (Read + Use)' \
  > ~/.config/relayforge/oauth-tunnel/runtime-key)
```

The new unit uses systemd `LoadCredential` to snapshot the new profile and runtime
key; its command contains only `file:%d/runtime-key`, never the secret. A clean
process environment prevents inherited target/key overrides. The native profile
may keep `api_key: env:CONTROL_PLANE_API_KEY` for manual `doctor`; the service
explicitly overrides that reference with its credential snapshot. If using
`doctor` after separate live-test authorization, pass only a **file reference**
with `--control-plane.api-key file:/ABSOLUTE/NEW/runtime-key`. It contacts the
control plane and is not an offline acceptance test. Supported user managers
may use `LoadCredentialEncrypted` and `systemd-creds encrypt --user` instead via
an attended unit override; do not silently convert or remove any existing key.

`relayforge-tunnel setup` is unnecessary for this new HTTP path. Retiring it for
existing stdio users would break the reviewed strict launcher contract in #110;
it remains in the package. No scripts copy credentials or migrate live state.

## Security behavior and verification

`--http-oauth` requires `RELAYFORGE_OAUTH_CONFIG_FILE`; missing/invalid provider
configuration or initial metadata/JWKS fetch fails startup, without falling back
to static authentication. `RELAYFORGE_HTTP_PORT` controls only the port, never the
bind address. The packaged unit supplies config through `LoadCredential`.

Unauthenticated GETs to `/.well-known/oauth-protected-resource` and its `/mcp`
variant return RFC 9728 metadata. All methods at `/mcp` require one bearer header;
query/body tokens are not accepted. Missing/invalid tokens receive 401 with
`WWW-Authenticate: Bearer resource_metadata=..., scope=...`; invalid tokens add
`invalid_token`. Insufficient scope returns 403 with `insufficient_scope`.
Authenticated standalone GET/DELETE remain 405 because this stateless transport
has no SSE subscription/session to delete. MCP protocol versions 2025-03-26,
2025-06-18 and 2025-11-25 are supported; 2026-07-28 is explicitly unsupported.
Host rebinding and browser Origin headers are refused; browser login takes place
at the IdP, not at loopback. OAuth mode uses the same restricted tool dispatcher
as the stdio tunnel, preserving all independent action/grant checks.

JWT verification uses jsonwebtoken with AWS-LC, fixed RS256, trusted-provider
JWKS and mandatory issuer/audience/subject/expiry. `nbf` is enforced when present;
clock leeway is zero. Keys cache for at most five minutes, with at most one fetch
attempt per 30 seconds (including unknown key IDs). Newly rotated IDs may need
30 seconds before acceptance. Failed refresh never extends stale trust: expired
cache returns 503, while fresh cached keys remain usable until their TTL. Tokens
are checked again on every call; there is no token-result cache. Short-lived JWTs
can remain usable until expiry/key-cache expiry after provider revocation; this
mode does not perform introspection. Configure short provider access lifetimes.
No tokens, provider response bodies or detailed upstream errors are logged.

Offline CI uses an in-memory disposable issuer and generated signing key, with
positive handshake/status, missing/invalid/forged/expired/future tokens,
issuer/audience/subject/scope, discovery, tool restrictions, rotation and outage
coverage. These checks establish source behavior only.

Live acceptance remains **BLOCKED** until a provider is configured and the owner
separately authorizes testing: verify real ChatGPT OAuth login/consent, the final
resource/audience after tunnel rewriting, `tools/list`, a safe `relayforge_status`
call, and rejection without/with invalid credentials. `doctor`, liveness and
local JWT fixtures do not establish that acceptance. After evidence and independent
review, an explicit owner decision must name any old tunnel/service cutover and
rollback. Keep current stdio configuration, keys, packages and services available
for rollback; do not automatically stop, remove or migrate them. Keep #114 open
for live acceptance and preserve #110/#89 evidence.

References: [MCP authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
[OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels),
[official v0.0.18 configuration](https://github.com/openai/tunnel-client/blob/v0.0.18/docs/configuration.md),
[official connector forwarding](https://github.com/openai/tunnel-client/blob/v0.0.18/docs/connectors.md),
[Keycloak OIDC discovery](https://www.keycloak.org/securing-apps/oidc-layers).
