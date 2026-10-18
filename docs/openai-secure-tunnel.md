# Connecting RelayForge to ChatGPT with Secure MCP Tunnel

The preferred remote transport is OpenAI Secure MCP Tunnel (outbound-only),
not an exposed SSH port, HTTP bearer gateway or homemade OAuth server.

Official docs:
https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md

The local stdio MCP command is:
`/home/user/Projects/relayforge/target/release/relayforge-mcp`

The verified official `tunnel-client` binary v0.0.16 (Linux amd64)
was installed outside the repository on ThinkPad at:
`/home/user/.local/libexec/relayforge/tunnel-client`
The zip checksum matched `SHA256SUMS.txt` from the same official release.

## User-side prerequisites

1. Create a tunnel in https://platform.openai.com/settings/organization/tunnels
   with Tunnels Read + Manage.
2. Create a **restricted runtime** API key with Tunnels Read + Use under
   https://platform.openai.com/settings/organization/api-keys
   for the same Platform organization.
3. Ensure ChatGPT workspace can use the tunnel and has permission to create
   a private custom MCP plugin. Do not publish it as a public plugin.
4. Enter the runtime key **locally** into a private credential store, not in
   chat, shell history, screenshots, repository, or a command argument.
   Never give the tunnel runtime an OpenAI Platform admin key.

When credentials are available, inspect:
```sh
~/.local/libexec/relayforge/tunnel-client help quickstart
~/.local/libexec/relayforge/tunnel-client init \
  --sample sample_mcp_stdio_local \
  --profile relayforge-local \
  --tunnel-id "tunnel_ID_FROM_PLATFORM" \
  --mcp-command "/home/user/Projects/relayforge/target/release/relayforge-mcp"
~/.local/libexec/relayforge/tunnel-client doctor \
  --profile relayforge-local --explain
```
The runtime API key must be provided through a protected local environment
reference when running doctor and the managed daemon; do not print it.
Only start the tunnel runtime after the profile and identity permissions
are reviewed. Confirm the local /readyz endpoint and real ChatGPT discovery
and tool invocation before calling remote access ready.

The tunnel is not yet provisioned; no tunnel process is running.
Until it is, this ChatGPT conversation does not have direct RelayForge tools.
