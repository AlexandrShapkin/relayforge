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
    python3 -B scripts/verify.py

# Explicit source build only: no installation, pointer update or service action.
release-build:
    cargo build --release --locked --target-dir .build/release -p relayforge-agent -p relayforge-mcp
