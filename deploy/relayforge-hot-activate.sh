#!/usr/bin/env bash
# Retired: this legacy helper coupled verification with live code replacement.
# No build, installation, grant change or restart is permitted here.
set -eu
echo "REFUSED: legacy hot activation is retired. Follow docs/runtime-artifacts.md with separate owner approval and verified rollback." >&2
exit 2
