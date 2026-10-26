# Package-managed Secure MCP Tunnel (Issue #110)

Source proposal only. Installation and live activation require a separately
attended owner decision after exact-head CI and independent acceptance.

RelayForge installs `relayforge-tunnel.service` in `/usr/lib/systemd/user`,
disabled by default, and `/usr/bin/relayforge-tunnel`. Optional `tunnel-client`
is a separate pacman package at **0.0.18-1**, independently versioned from
RelayForge. Its upstream archive is the official
[OpenAI v0.0.18 release](https://github.com/openai/tunnel-client/releases/tag/v0.0.18),
commit `274a5588414819f063d27100a4fb1096aae3830f`, SHA-256
`3c82307316acd93c88a384b62af1d81d3f4cb0efa975f9c0bfaef922866a04c4`.
`packaging/arch/tunnel-client/upstream.json` pins the archive, checksum manifest
and provenance bundle. Both the build wrapper and PKGBUILD verify GitHub/Sigstore
provenance against the official release workflow, exact tag, source/signer commit
and hosted runner policy. Missing trust material or verification support fails
closed. Matching checksums from one server alone do not establish provenance.
The upstream cloudflared companion, notices, license report, SPDX SBOM, manifest
and provenance remain package owned. The companion lives beside the real client
under `/usr/lib/tunnel-client`, avoiding a conflict with a standalone cloudflared.

The launcher requires intact pacman packages and the supported client version;
Packaging-only pkgrel updates are accepted; future upstream version upgrades need their own reviewed lock/recipe/compatibility change.
It validates private, ordinary, user-owned 0600 files through no-follow dirfds
under a private 0700 `~/.config/relayforge/managed-tunnel` directory. The new
JSON profile is valid YAML and permits only one stdio target:
`/usr/bin/relayforge-mcp --readonly-stdio`. Extra channels, HTTP targets,
unsafe modes, hardlinks and symlinks fail closed. Inherited tunnel/client proxy,
profile, MCP and debugging environment overrides are discarded. Direct launcher use keeps validated descriptors across exec. For the user unit,
an ordinary-user `ExecCondition` with the systemd `+` prefix validates packages
outside the client's filesystem/user namespace: inside that namespace, host root
ownership is unmapped and pacman's ownership checks would falsely fail. The
prefix grants no host root privilege in a user manager. All package checks remain
mandatory. `LoadCredential` provides read-only per-invocation profile/key
snapshots, which the condition compares byte-for-byte with the no-follow source
descriptors. The hardened client receives only those snapshots and a fixed stdio
command through a clean environment; its namespace restrictions remain enabled. This does
not defend against a malicious process with the same UID changing file contents.

## Explicit migration, physical terminal only

1. Inventory loaded user/system units, user overrides, timers, processes,
   executable paths and pacman ownership locally. Keep output private. If a
   legacy `relayforge-tunnel.service` override or process exists, stop here:
   obtain separately approved exact retirement scope and rollback evidence.
   A user override masks the packaged unit; installing it does not migrate one.
2. Preserve all legacy profiles, credentials, shared `~/.config/tunnel-client`,
   `.local/libexec/relayforge`, grants, runtime selectors and historical evidence.
   Do not copy old credentials. Review the old profile locally, redacting IDs,
   secrets, private endpoints and unrelated settings before any diff is shared.
   The new example contract below replaces only the command/transport; it does
   not silently carry forward old channels, proxies or authorization.
3. After package/release verification and separate installation consent,
   install **both** reviewed pacman packages from the same release manifest.
   `pacman -Qkk relayforge tunnel-client` must pass. Installation never enables
   or starts either service. No package hooks or private config files are shipped.
4. `relayforge-tunnel plan` prints a read-only migration outline. At the physical
   terminal, ensure `~/.config/relayforge` exists with owner-controlled parents,
   then run `relayforge-tunnel setup --tunnel-id YOUR_NEW_OR_REVIEWED_TUNNEL_ID`.
   Review the displayed boundary, type the exact confirmation, and enter a
   **fresh** runtime key with only Tunnels Read + Use through the hidden prompt.
   Never use an admin key. Setup refuses existing destinations and noninteractive
   input; it never imports, modifies or deletes legacy data or service state.
   Interrupted partial setup is retained for owner inspection, never auto-removed.
5. Inspect the newly created files locally without publishing secrets.
   `relayforge-tunnel check` validates installation and the strict profile.
   `systemctl --user cat relayforge-tunnel.service` must resolve to the packaged
   unit without unknown overrides. Only separate live authorization permits a
   manual start. There is no enable/start command in setup, upgrade or removal.
6. Successful authenticated control-plane polling, real ChatGPT tool calls,
   restriction checks, artifact access/revocation and independent rollback remain
   separate physical-host acceptance gates. CI cannot certify them.

Readable profile shape (the helper writes the absolute key path):

```json
{
  "config_version": 1,
  "control_plane": {
    "tunnel_id": "tunnel_00000000000000000000000000000000",
    "api_key": "file:/home/OWNER/.config/relayforge/managed-tunnel/runtime-key"
  },
  "mcp": {"commands": [{"channel": "main", "command": "/usr/bin/relayforge-mcp --readonly-stdio"}]},
  "health": {"listen_addr": "127.0.0.1:0"},
  "log": {"level": "info", "format": "json"}
}
```

## Updates, removal and rollback

Pacman updates replace package-owned files only. They never reuse or rotate keys,
change profiles or activate services. Stop a running tunnel only with separate
owner authorization before an update/removal: removing an executable does not
stop an already running process. A stale loaded user unit needs an attended
`daemon-reload`; do not infer activation permission. Remove the optional client
independently with pacman; keep all profiles and evidence. Existing user-data
purge deliberately excludes tunnel profiles and keys. Downgrade both packages
to previously verified compatible versions as required; this restores owned
files, not credentials, service state or live recovery health.

CI exercises both installed packages, denied starts and supply-chain failures
inside disposable containers. Native Rust/security gates and the existing
reviewed-main release workflow remain mandatory. No additional publisher,
manual release path, host install or live tunnel activation is introduced.
