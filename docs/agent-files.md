# Restricted agent file pilot

The MCP tool `relayforge_agent_file` implements:
- `file.read` with a literal allowed OS metadata path:
  `/etc/hostname`, `/etc/os-release`, `/proc/loadavg`,
  `/proc/meminfo`, or `/proc/uptime`.
- `file.list` for a dedicated scratch directory.
- `file.create` for a new, unique, small text, Markdown, or JSON file
  inside the scratch directory, with no overwrites.

The scratch directory is fixed:
`/home/shapkin_as/.local/share/relayforge/pilot-files`
and must already exist, mode 0700, under the SSH user's account.
It is never an arbitrary caller-supplied directory. Only flat ASCII
filenames ending `.txt`, `.md`, `.json` and <=64 bytes are allowed.
Files are capped at 2 KiB on creation, 8 KiB on read, quota 32 entries.
Existing files are never truncated. Symlinked scratch directories or
files are rejected, as are group/world-accessible scratch files.

**Security boundary**: this is a dedicated throwaway workspace for
testing a very limited file-write operation. It cannot alter user data,
application configs, SSH keys, services, the router, or files elsewhere.
This pilot inherits the authenticated local Unix/SSH identity and is
not a per-actor production authorization system. Broader files and
service mutations remain blocked until distinct actor authorization,
per-device grants and auditing are implemented.

## Hardened local HTTP deployment

The MCP SSH wrappers explicitly read the local private
`~/.ssh/config` file (`ssh -F`) to avoid distribution-generated system
SSH config symlinks being rejected inside systemd mount namespaces.
This preserves strict host-key validation and permits systemd hardening
(`ProtectHome=read-only`, `ProtectSystem=full`, `NoNewPrivileges=true`).
