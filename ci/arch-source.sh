#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -ne 0
test -n "${CARGO_TARGET_DIR:?isolated target required}"
test "$(git rev-parse HEAD)" = "${SOURCE_SHA:?exact source SHA required}"
mkdir -p .build/arch-dist
pacman -Q > .build/arch-dist/arch-packages.txt
rustc -Vv > .build/arch-dist/rustc.txt
cargo build --release --locked -p relayforge-mcp -p relayforge-agent
# Full workspace/systemd gates stay on Ubuntu; do not skip/relax them there.
cargo test --locked -p relayforge-mcp
for suite in process_roles runtime_artifact activation_transaction attended_activation attended_upgrade source_package; do
    python3 -B -m unittest discover -s scripts -p "test_${suite}.py"
done
python3 -B scripts/offline_mcp_smoke.py "$CARGO_TARGET_DIR/release/relayforge-mcp"
python3 -B scripts/offline_artifact_acceptance.py "$CARGO_TARGET_DIR/release/relayforge-mcp"
python3 -B scripts/source_package.py build --binary "$CARGO_TARGET_DIR/release/relayforge-mcp" --output .build/arch-package
cp .build/arch-package/* .build/arch-dist/
sha=$(git rev-parse HEAD)
tar -C "$CARGO_TARGET_DIR/release" -czf ".build/arch-dist/relayforge-arch-binaries-$sha.tar.gz" relayforge-mcp relayforge-agent
(cd .build/arch-dist && sha256sum ./*.tar.gz > SHA256SUMS)
