#!/usr/bin/env bash
# Run INTERACTIVELY on ThinkPad once a restricted OpenAI Platform runtime key
# with Tunnels Read + Use has been created. Never copy the key into chat.
set -euo pipefail
umask 077

CLIENT="$HOME/.local/libexec/relayforge/tunnel-client"
SECRET_DIR="$HOME/.config/relayforge/tunnel"
KEY_FILE="$SECRET_DIR/runtime-key"

if [[ ! -t 0 || ! -t 1 ]]; then
    echo "Run this command interactively in the ThinkPad terminal." >&2
    exit 1
fi
if [[ ! -x "$CLIENT" ]]; then
    echo "OpenAI tunnel-client is not installed." >&2
    exit 1
fi
if [[ -e "$KEY_FILE" ]]; then
    echo "A runtime key file already exists. Refusing to overwrite it." >&2
    exit 1
fi

install -d -m 700 "$SECRET_DIR"
IFS= read -r -s -p "Restricted OpenAI Platform runtime API key (input hidden): " TOKEN
printf '\n'
if [[ "${#TOKEN}" -lt 20 || "$TOKEN" != sk-* || "$TOKEN" == *[[:space:]]* ]]; then
    unset TOKEN
    echo "Invalid key format. No file created." >&2
    exit 1
fi

# Write only to a private file; the key never appears in a command argument,
# shell history, process title, log, or this chat.
printf '%s\n' "$TOKEN" > "$KEY_FILE"
unset TOKEN
chmod 600 "$KEY_FILE"

echo "Checking local MCP and OpenAI tunnel permissions..."
if ! "$CLIENT" doctor --profile relayforge-local --explain; then
    echo "Doctor failed. Tunnel not started. Review key permissions and connectivity." >&2
    echo "Private key retained at $KEY_FILE for a later retry." >&2
    exit 2
fi

systemctl --user daemon-reload
systemctl --user enable --now relayforge-tunnel.service

# Starting successfully only means systemd launched the binary. Require
# evidence of authenticated control-plane polling before claiming readiness.
HEALTH_FILE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/relayforge-tunnel/health.url"
ready=false
for attempt in {1..30}; do
    if "$CLIENT" health --url-file "$HEALTH_FILE" \
        --require-control-plane-poll >/dev/null 2>&1; then
        ready=true
        break
    fi
    if ! systemctl --user is-active --quiet relayforge-tunnel.service; then
        echo "Tunnel process stopped before its first successful poll." >&2
        systemctl --user show relayforge-tunnel.service -p ActiveState -p SubState -p NRestarts
        exit 3
    fi
    sleep 3
done
if [[ "$ready" != true ]]; then
    echo "Tunnel is running, but a successful OpenAI control-plane poll was not confirmed." >&2
    echo "Inspect the user service logs without printing runtime credentials." >&2
    exit 4
fi

echo "Secure MCP Tunnel is healthy, ready and has completed a successful control-plane poll."
systemctl --user show relayforge-tunnel.service -p ActiveState -p SubState -p NRestarts
echo "Complete private MCP plugin discovery in ChatGPT and verify an actual tool call."
