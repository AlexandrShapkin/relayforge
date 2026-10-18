# Android support

## Current: local authorized ADB pilot

The local stdio MCP adapter offers:
- `relayforge_android_devices` (no arguments): list authorized ADB serials.
- `relayforge_android_diagnostic` (serial, check): read model, Android
  version, battery, uptime and storage for a listed device.

Only devices already authorized with Android's ADB trust prompt are visible.
ADB can connect via USB or Android's official paired wireless debugging,
but **do not expose legacy plaintext TCP debugging or automatically pair devices**.
The bridge does not execute arbitrary commands, install APKs, send touches,
change settings or elevate privileges. Results are limited to 16 KiB and
each operation times out. The host's ADB server and OS identity constitute
the trust boundary: use only with trusted local MCP clients.

No Android device was connected to ThinkPad at the time of implementation.
The parser and authorization checks have unit tests, but a live Android
integration test is still needed.

## Planned: direct Android companion agent

For devices not attached to the development machine, use a small Android app
with an outbound authenticated session to the RelayForge coordinator.
Android's permission model determines what can be implemented without
ADB, root, or device-owner privileges. Never assume an agent can access
other apps' private data, capture the screen, or silently perform input.

Keep independent capability grants per authenticated actor/device:
`android.device.read`, `android.apps.list`, `android.files.read`,
`android.files.write`, `android.app.launch` and
`android.screen.capture` (the latter requires explicit user consent and
Android MediaProjection permissions). Sensitive changes require visible
approval on the device; default deny all mutating operations.

Do not rely on permanent background execution: implement reconnect,
Android foreground-service policy compliance, and battery-aware intervals.
Avoid accessibility-service automation as a substitute for ordinary
permissions unless the user explicitly enables a legitimate use case.
