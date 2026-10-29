# Ubuntu 24.04 source package (Issue #116)

This is **source/CI preparation**, not an authorization to deploy on ru0.
The immutable publisher retains all Arch gates and adds a source-versioned Ubuntu release contract.

ci/ubuntu_package.py consumes relayforge-mcp and relayforge-agent binaries
compiled by the **same exact-head** Ubuntu 24.04 CI verification job. It refuses a
dirty checkout, an incorrect SHA, a different build OS/architecture or missing
executables. It binds both binary digests and the full source commit to
source.json and produces relayforge_VERSION_amd64.deb and SHA256SUMS.
The revision-based version is shared with the Arch source identity and does not
claim bit-for-bit reproducibility.

The package owns only its two Rust binaries, the bounded user-data helper,
three disabled systemd **user** unit templates, public OAuth examples and
operational docs. It contains no maintainer scripts, service enablement, keys,
grants, profile contents, arbitrary SSH config or runtime state. The OAuth
resource always binds loopback; a user service cannot become a public listener.
The optional tunnel HTTP unit requires a **separately installed and independently
verified** official tunnel-client; it is not provided by this package.
Do not use the Arch-only relayforge-tunnel helper on Ubuntu.

CI installs the assembled .deb with dpkg -i inside disposable Ubuntu 24.04,
validates inventory and no maintainer scripts, executes the installed restricted
stdio MCP/agent and negative authorization tests, verifies all units and package
ownership, and purges only owned files while preserving an unrelated user file.
A separate `ubuntu-release` job downloads those exact package bytes and repeats
installed-package, restricted MCP, negative authorization and removal checks in
a fresh disposable Ubuntu container. It binds success to the package SHA-256 and
full source SHA in `ubuntu-verification.json`; it never rebuilds the package.

For source revisions containing `ci/ubuntu_release.py`, immutable release
publication requires this additional successful job alongside every existing
Rust, security, sandbox and Arch gate and independent exact-head PR acceptance.
The publisher downloads only the independently verified Ubuntu artifact from the
accepted exact-main run. It validates its original checksums, source identity,
architecture and receipt before generating provenance. The `.deb`, namespaced
`ubuntu-source.json`, `ubuntu-SHA256SUMS` and `ubuntu-verification.json` join the
existing release inventory. The attested top-level `SHA256SUMS` authenticates all
of these files; the `.deb` also receives package provenance. No package execution
occurs in the privileged publisher.

Historical source without this contract retains its original Arch-only inventory
and provenance validation. Existing releases are never retrofitted or overwritten;
historical validation needs authenticated Release assets, not expired CI artifacts.
Missing unpublished artifacts, provenance, independent review or successful checks
block publication and require reconciliation. This source task grants no manual
release publication, deployment or service activation authority.

## Before any future ru0 activation

1. Obtain independent exact-head acceptance and successful mandatory CI for
   the Ubuntu release/provenance stage; owner authorization to merge remains separate.
2. Independently review a tested Ubuntu deployment/rollback path and official
   tunnel-client installation, separate from Arch pacman commands.
3. Provision Keycloak through its own restricted HTTPS endpoint, with backed-up
   state and owner-specific OAuth audience/subject/scope; never make MCP public.
4. With separate host approval, inspect active ru0 services/configuration and
   establish recovery that does not depend on the MCP/tunnel being upgraded.
   Keep its SSH, VPN, Nginx and Assistant Hub services unchanged.
5. In a separately authorized test tunnel, verify real ChatGPT login, tools/list,
   safe relayforge_status, authorization failure, remote routing, client
   reconnect and rollback. Retain the existing ThinkPad tunnel until explicit
   independent owner cutover. The ThinkPad file/Android/Codex operations cannot
   be served by a VPS without an authenticated per-host agent and local policy.

A successful dpkg transaction is neither a live MCP acceptance receipt nor
permission to restart a service. Services are not automatically enabled and no
loginctl enable-linger is performed by packaging.
