#!/bin/sh
# Separate entrypoint for remotely reachable private tunnel transport.
# This intentionally excludes all local-only write and restart tools.
set -eu
exec /home/user/Projects/relayforge/target/release/relayforge-mcp --readonly-stdio
