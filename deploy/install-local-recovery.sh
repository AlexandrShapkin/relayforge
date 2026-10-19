#!/usr/bin/env bash
# Local operator bootstrap only. No remote MCP approval, no SSH and no keys.
set -Eeuo pipefail
umask 077

[[ $# -eq 0 ]] || { echo "No arguments accepted" >&2; exit 2; }
[[ "$(id -u)" != 0 ]] || { echo "Install as an ordinary user" >&2; exit 2; }

repo="$HOME/Projects/relayforge"
grant="$HOME/.config/relayforge/allow-self-recovery"
target="$HOME/.local/libexec/relayforge"
systemd="$HOME/.config/systemd/user"

[[ -f "$grant" && ! -L "$grant" ]] || {
  echo "Local self-recovery grant missing; no services installed" >&2
  exit 3
}
[[ "$(stat -c '%a' "$grant")" == 600 &&
   "$(stat -c '%u' "$grant")" == "$(id -u)" ]] || {
  echo "Unsafe local grant ownership or permissions" >&2
  exit 3
}
[[ "$(cat "$grant")" == "ALLOW_RELAYFORGE_SELF_RECOVERY" ]] || {
  echo "Local self-recovery grant content mismatch" >&2
  exit 3
}
[[ -d "$repo" && -f "$repo/deploy/relayforge-local-recover.py" ]] || {
  echo "Expected local checkout unavailable" >&2
  exit 4
}
[[ -d "$HOME/.local/state/relayforge" &&
   ! -L "$HOME/.local/state/relayforge" ]] || {
  echo "Private state directory unavailable" >&2
  exit 4
}
mkdir -p -m 700 "$target" "$systemd"
[[ ! -L "$target" && ! -L "$systemd" ]] || exit 5
install -m 700 "$repo/deploy/relayforge-local-recover.py" \
  "$target/relayforge-local-recover.py"
install -m 600 "$repo/deploy/systemd/relayforge-local-recover.service" \
  "$systemd/relayforge-local-recover.service"
install -m 600 "$repo/deploy/systemd/relayforge-local-recover.timer" \
  "$systemd/relayforge-local-recover.timer"
python3 "$target/relayforge-local-recover.py" check
systemctl --user daemon-reload
systemctl --user enable --now relayforge-local-recover.timer
echo "Local recovery guard installed; tunnel has not been restarted."
