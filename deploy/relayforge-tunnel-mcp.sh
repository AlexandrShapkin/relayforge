#!/bin/sh
# Install only during a separately approved runtime migration.
set -eu
exec "$HOME/.local/libexec/relayforge/runtime/current/relayforge-mcp" --readonly-stdio
