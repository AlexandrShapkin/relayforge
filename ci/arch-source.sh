#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" -ne 0
test -n "${CARGO_TARGET_DIR:?isolated target required}"
test "$(git rev-parse HEAD)" = "${SOURCE_SHA:?exact source SHA required}"
# A release can never contain unstaged/untracked source or owner-local ignored files.
test -z "$(git status --porcelain --untracked-files=normal)"
mkdir -p .build/arch-dist .build/makepkg
pacman -Q > .build/arch-dist/arch-packages.txt
rustc -Vv > .build/arch-dist/rustc.txt
# Preserve existing operational source verification without a duplicate compilation.
# The package recipe itself compiles the committed source and owns its target dir.
git archive --format=tar HEAD > .build/makepkg/relayforge-source.tar
python3 -B ci/package_identity.py .build/makepkg
(cd .build/makepkg && makepkg --noconfirm --cleanbuild)
cp .build/makepkg/*.pkg.tar.zst .build/arch-dist/
# Native MCP suite plus the existing portable operational contract.
export CARGO_TARGET_DIR="$PWD/.build/makepkg/src/target"
cargo test --locked -p relayforge-mcp
for suite in process_roles runtime_artifact activation_transaction attended_activation attended_upgrade source_package arch_packaging; do
    python3 -B -m unittest discover -s scripts -p "test_${suite}.py"
done
python3 -B scripts/source_package.py build --binary "$CARGO_TARGET_DIR/release/relayforge-mcp" --output .build/arch-package
cp .build/arch-package/* .build/arch-dist/
python3 -B ci/verify_extracted_bundle.py ".build/arch-dist/relayforge-arch-source-v1-$SOURCE_SHA.tar.gz" "$SOURCE_SHA"
(cd .build/arch-dist && sha256sum ./*.pkg.tar.zst ./*.tar.gz arch-packages.txt rustc.txt source.json > SHA256SUMS)
