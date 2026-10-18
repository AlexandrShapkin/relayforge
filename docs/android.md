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

## Privacy-filtered Android health tool

relayforge_android_health is a new no-argument, read-only MCP tool that
discovers devices already authorized in the local ADB server. It refuses
unexpected arguments, caps inspection at four devices, and runs a fixed
set of existing ADB diagnostic probes per device: model, Android version,
dumpsys battery, and df /data.

The response contains only device serial, product model, Android version,
battery percentage, charging state, free storage in MiB and bounded
findings. It does not return raw dumpsys data, filesystem paths from
the device, installed app lists, contacts, location, screen contents,
messages, passwords, Wi-Fi keys or private application data.

Health states:
- no_authorized_devices: no live authorized ADB devices were found;
  this is not healthy, and the Android connection is not yet tested.
- healthy: a device returned complete readings and has sufficient power
  and storage for ordinary diagnostics.
- attention: battery is below 15%, or free storage is below 512 MiB.
- unverified: an ADB probe fails or is missing expected fields.
- capacity_exceeded: more than four authorized devices; no partial
  health snapshot is presented as complete.

The tool never performs ADB pairing, connects to remote TCP endpoints,
sends input events or changes device settings. Android Debug Bridge
authorization must be granted by the physical device user, using USB
debugging or the official paired wireless debugging flow.

The implementation has mock-output tests for battery/charging, capacity,
incomplete probes and malicious metadata. At deployment time no Android
device was authorized on ThinkPad; real-device tests remain required.

## Next implementation step

A direct companion app can eventually offer better Android visibility
when the phone is away from ThinkPad. Do not assume that privileged
device commands are possible without consent: Android's app sandbox,
foreground-service and runtime permission rules apply.

Mutating operations such as package installation, app launch, device
configuration, file writes or screenshots are **not enabled**. Any
future mutation needs per-device capability policy, explicit operator
approval, an audited one-time grant and a failure/recovery plan.
