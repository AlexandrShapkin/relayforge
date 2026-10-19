# Contributing to RelayForge

RelayForge is security-sensitive infrastructure software. Keep contributions narrow and preserve deny-by-default access controls.

## Workflow

1. Create a short-lived branch from `main`.
2. Explain the motivation and security implications in the pull request.
3. Add tests and documentation when behavior changes.
4. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`.
5. Describe deployment and rollback when applicable.

Never commit credentials, SSH keys, ADB authorizations, private device data, or production configurations. Changes to permissions and approval flows require explicit security review.

See [security](docs/security.md) and [development](docs/development-without-rdc.md).
