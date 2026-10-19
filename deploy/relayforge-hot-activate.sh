#!/usr/bin/env bash
# One-time migration from a legacy MCP process to the persistent hot-stdio
# parent. Run as the authorized local ThinkPad user after CI review.
# No SSH keys, Platform credentials, or tunnel profile values are needed.
set -Eeuo pipefail
umask 077

[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Usage: relayforge-hot-activate.sh EXPECTED_MAIN_SHA" >&2
    exit 2
}
repo="$HOME/Projects/relayforge"
state="$HOME/.local/state/relayforge"
binary="$repo/target/release/relayforge-mcp"
backup="$state/mcp-before-hot-activation"
known_good="$state/mcp-hot-last-good"
client="$HOME/.local/libexec/relayforge/tunnel-client"
url_file="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/relayforge-tunnel/health.url"

cd "$repo"
[[ "$(git branch --show-current)" == "main" ]] || { echo "Not on main" >&2; exit 3; }
[[ "$(git rev-parse HEAD)" == "$1" ]] || { echo "Unexpected commit" >&2; exit 4; }
git diff --quiet HEAD -- || { echo "Tracked checkout is dirty" >&2; exit 5; }
[[ -x "$binary" && -x "$client" ]] || { echo "Required executable missing" >&2; exit 6; }
[[ -d "$state" && ! -L "$state" ]] || { echo "Private state unavailable" >&2; exit 7; }

# A prior build may already have replaced the release file. Preserve the
# *running legacy tunnel MCP executable*, not the current on-disk build.
# /proc/PID/exe still references the mapped legacy image after replacement.
[[ ! -e "$known_good" ]] || {
    echo "Hot parent was already activated; refusing to overwrite rollback" >&2
    exit 9
}
parent_pid=""
while IFS= read -r pid; do
    if [[ -r "/proc/$pid/cmdline" ]] &&
       tr '\0' '\n' < "/proc/$pid/cmdline" | grep -Fxq -- "--readonly-stdio"; then
        [[ -z "$parent_pid" ]] || {
            echo "Ambiguous active tunnel MCP processes" >&2
            exit 10
        }
        parent_pid="$pid"
    fi
done < <(pgrep -u "$(id -u)" -x relayforge-mcp || true)
[[ -n "$parent_pid" && -r "/proc/$parent_pid/exe" ]] || {
    echo "Cannot locate the mapped legacy tunnel MCP binary" >&2
    exit 11
}
install -m 700 "/proc/$parent_pid/exe" "$backup.pending"
mv -f "$backup.pending" "$backup"
# The backup must still behave as a restricted MCP adapter.
printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' |
    timeout 20s "$backup" --readonly-stdio |
    python3 -c 'import json,sys; d=json.load(sys.stdin); assert any(t["name"]=="relayforge_workstation_develop" for t in d["result"]["tools"])'
restarted=0
rollback() {
    echo "Activation failed: attempting to restore the previous restricted MCP." >&2
    if [[ -f "$backup" ]]; then
        install -m 700 "$backup" "$binary.rollback"
        mv -f "$binary.rollback" "$binary"
        if [[ "$restarted" == 1 ]]; then
            systemctl --user restart relayforge-tunnel.service || true
        fi
    fi
}
trap rollback ERR

cargo build --release --locked -p relayforge-agent -p relayforge-mcp
python3 scripts/offline_mcp_smoke.py "$binary"

# The new hot parent must start and answer a request using a separate worker.
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' |
    timeout 20s "$binary" --readonly-stdio |
    python3 -c 'import json,sys; data=json.load(sys.stdin); names={x["name"] for x in data["result"]["tools"]}; assert "relayforge_workstation_develop" in names'

restarted=1
systemctl --user restart relayforge-tunnel.service

healthy=0
for attempt in {1..30}; do
    if "$client" health --url-file "$url_file" --require-control-plane-poll --json 2>/dev/null |
        python3 -c 'import json,sys,time; v=json.load(sys.stdin); t=float(v["control_plane_poll"]["value"]); assert v["result"]=="ok" and 0 <= time.time()-t <= 30' 2>/dev/null; then
        healthy=1
        break
    fi
    sleep 3
done
if [[ "$healthy" != 1 ]]; then
    echo "No fresh authenticated poll after restart" >&2
    rollback
    exit 8
fi

install -m 700 "$binary" "$known_good"
trap - ERR
echo "HOT_STDIO_ACTIVATED commit=$1"
echo "Further RelayForge builds must not restart the tunnel service."
