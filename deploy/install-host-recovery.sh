#!/usr/bin/env bash
# Run locally on ru0 as the owner of the user services. Never over MCP/CI.
set -Eeuo pipefail
umask 077

[[ $# -eq 0 && "$(id -u)" != 0 ]] || {
  echo "Local non-root installation only; no arguments accepted" >&2; exit 2;
}
[[ "$(hostname -s)" == "ru0" ]] || {
  echo "Host mismatch: recovery is scoped to ru0" >&2; exit 3;
}
[[ "$(loginctl show-user "$(id -un)" --property=Linger --value 2>/dev/null)" == yes ]] || {
  echo "User lingering not enabled; reboot-independent timer cannot be verified" >&2; exit 4;
}

source_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
grant="$HOME/.config/relayforge/allow-host-recovery"
target="$HOME/.local/libexec/relayforge"
state="$HOME/.local/state/relayforge-host-recovery"
units="$HOME/.config/systemd/user"

[[ -f "$grant" && ! -L "$grant" &&
   "$(stat -c '%u' "$grant")" == "$(id -u)" &&
   "$(stat -c '%a' "$grant")" == "600" &&
   ]] && cmp -s "$grant" <(printf '%s\n' "ALLOW_RELAYFORGE_HOST_RECOVERY") || {
  echo "Exact local opt-in grant absent or unsafe" >&2; exit 5;
}
[[ -f "$source_dir/relayforge-host-recovery.py" &&
   -f "$source_dir/systemd/relayforge-host-recovery.service" &&
   -f "$source_dir/systemd/relayforge-host-recovery.timer" ]] || {
  echo "Reviewed deployment sources missing" >&2; exit 6;
}
for path in "$HOME/.config" "$HOME/.config/relayforge" \
            "$HOME/.local" "$HOME/.local/state" \
            "$HOME/.local/libexec" "$HOME/.config/systemd"; do
  [[ -d "$path" && ! -L "$path" ]] || {
    echo "Unsafe or missing parent directory" >&2; exit 7;
  }
done

mkdir -p -m 700 "$target" "$state" "$units"
for path in "$target" "$state" "$units"; do
  [[ -d "$path" && ! -L "$path" &&
     "$(stat -c '%u' "$path")" == "$(id -u)" ]] || {
    echo "Unsafe destination" >&2; exit 8;
  }
done
chmod 700 "$state"
for path in "$target/relayforge-host-recovery.py" \
            "$units/relayforge-host-recovery.service" \
            "$units/relayforge-host-recovery.timer"; do
  [[ ! -L "$path" ]] || { echo "Symlink destination denied" >&2; exit 9; }
done

install -m 700 "$source_dir/relayforge-host-recovery.py" \
  "$target/relayforge-host-recovery.py"
install -m 600 "$source_dir/systemd/relayforge-host-recovery.service" \
  "$units/relayforge-host-recovery.service"
install -m 600 "$source_dir/systemd/relayforge-host-recovery.timer" \
  "$units/relayforge-host-recovery.timer"

python3 "$target/relayforge-host-recovery.py" check
systemctl --user daemon-reload
systemctl --user enable --now relayforge-host-recovery.timer
echo "Host-local guard timer enabled; production services have not been modified."
