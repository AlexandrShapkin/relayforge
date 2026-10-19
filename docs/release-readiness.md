# Release readiness checklist

RelayForge is in active development. Do not create a public release or tag until all relevant checks are complete.

- [ ] Confirm the full Apache-2.0 license text is included in a root `LICENSE` file and attribution obligations are reviewed.
- [ ] Verify Rust formatting, Clippy, tests, and release builds on the release commit.
- [ ] Verify read-only MCP tunnel behavior and that standard output is protocol-only.
- [ ] Review host allowlists, local interactive approvals, and audit boundaries.
- [ ] Verify real-device diagnostics only on authorized devices.
- [ ] Scan repository and release artifacts for secrets and private infrastructure identifiers.
- [ ] Prepare versioned release notes, compatibility information, and known limitations.
- [ ] Create an annotated tag and GitHub prerelease only after validation.

## GitHub repository presentation

Suggested description: **Security-first Rust MCP bridge for controlled diagnostics and human-approved operations across personal infrastructure.**

Suggested topics: `rust`, `mcp`, `model-context-protocol`, `infrastructure`, `security`, `linux`, `mikrotik`, `android`, `observability`, `homelab`.

Upload a social preview image in repository **Settings → General → Social preview**. The tracked `assets/relayforge-banner.svg` is a visual source; GitHub social preview upload may require a raster PNG/JPEG. Do not claim the preview is configured until the setting has been verified.
