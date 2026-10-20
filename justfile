# Fixed local developer commands. Actual source/Git trust and remote CI are external gates.
default:
    @just --list

status:
    python3 -B scripts/development_interface.py relayforge status

context:
    python3 -B scripts/development_interface.py relayforge context

doctor:
    python3 -B scripts/development_interface.py relayforge doctor

docs-check:
    python3 -B scripts/development_interface.py relayforge docs-check

# Native full offline verification: Rust checks AND recovery, release build,
# denied MCP smoke, without hardware. Real-device proof stays separate.
verify: docs-check
    bash -n deploy/relayforge-hot-activate.sh
    bash -n deploy/install-local-recovery.sh
    python3 -B -m py_compile deploy/relayforge-local-recover.py scripts/test_local_recovery.py
    python3 -B scripts/test_local_recovery.py
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked
    cargo build --release --locked -p relayforge-agent -p relayforge-mcp
    python3 -B scripts/offline_mcp_smoke.py target/release/relayforge-mcp
