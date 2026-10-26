#!/usr/bin/python3
"""Package-managed tunnel guard and attended fresh setup; never touch legacy state."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import pwd
import stat
import subprocess
import sys

CLIENT = '/usr/bin/tunnel-client'
COMMAND = '/usr/bin/relayforge-mcp --readonly-stdio'
RELATIVE = '.config/relayforge/managed-tunnel'
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class Refused(ValueError):
    """Fixed diagnostic category; never includes private input or subprocess text."""


def directory(home):
    # Traverse from / using dirfds; refuse symlinked or writable ancestors.
    fd = os.open('/', FLAGS | os.O_DIRECTORY)
    try:
        for part in [*Path(home).parts[1:], *RELATIVE.split('/')]:
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky):
                raise ValueError('unsafe directory')
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('managed directory must be private and user owned')
        return fd
    except BaseException:
        os.close(fd)
        raise


def private(fd, name):
    child = os.open(name, FLAGS, dir_fd=fd)
    try:
        info = os.fstat(child)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= 16384):
            raise ValueError('unsafe private file')
        data = os.read(child, 16385)
        return child, data
    except BaseException:
        os.close(child)
        raise


def profile(tunnel_id, key):
    if not re.fullmatch(r'tunnel_[A-Za-z0-9]{16,64}', tunnel_id):
        raise ValueError('invalid tunnel ID')
    return {'config_version': 1,
            'control_plane': {'tunnel_id': tunnel_id, 'api_key': 'file:' + key},
            'mcp': {'commands': [{'channel': 'main', 'command': COMMAND}]},
            'health': {'listen_addr': '127.0.0.1:0'},
            'log': {'level': 'info', 'format': 'json'}}


def checked(home):
    fd = directory(home)
    opened = []
    try:
        for name in ('profile.json', 'runtime-key'):
            child, data = private(fd, name)
            opened.append(child)
            if name == 'profile.json':
                config = json.loads(data)
            elif not data.strip() or b'\n' in data.strip() or b'\x00' in data:
                raise ValueError('invalid runtime key')
        expected = profile(config['control_plane']['tunnel_id'], str(Path(home) / RELATIVE / 'runtime-key'))
        if config != expected:
            raise ValueError('profile differs from restricted contract')
        return opened
    except BaseException:
        for child in opened:
            os.close(child)
        raise
    finally:
        os.close(fd)


def package_check():
    for package in ('relayforge', 'tunnel-client'):
        subprocess.run(['/usr/bin/pacman', '-Qkk', package], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    version = subprocess.check_output(['/usr/bin/pacman', '-Q', 'tunnel-client'], text=True).strip()
    if not re.fullmatch(r'tunnel-client 0\.0\.18-[1-9][0-9]*', version):
        raise ValueError('unsupported upstream version; independently review an upstream update')
    for name in ('/usr/lib/tunnel-client/tunnel-client', '/usr/lib/tunnel-client/cloudflared',
                 '/usr/bin/relayforge-mcp'):
        info = os.stat(name, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('unsafe installed executable')
    if Path(CLIENT).resolve() != Path('/usr/lib/tunnel-client/tunnel-client'):
        raise ValueError('unexpected client selector')


def launch(home, check_only=False):
    try:
        package_check()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise Refused('installed-package') from None
    try:
        opened = checked(home)
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused('private-profile-or-key') from None
    if check_only:
        for fd in opened:
            os.close(fd)
        return
    # Profile is already validated. Use fixed CLI target/key references to the
    # opened descriptors; no path replacement between validation and key read.
    for fd in opened:
        os.set_inheritable(fd, True)
    args = [CLIENT, 'run', '--config', f'/proc/self/fd/{opened[0]}',
            '--control-plane.api-key', f'file:/proc/self/fd/{opened[1]}',
            '--mcp.command', f'command={COMMAND},channel=main']
    try:
        os.execve(CLIENT, args, {'HOME': home, 'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    except OSError:
        raise Refused('client-exec') from None


def setup(home, tunnel_id):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('attended physical terminal required')
    target = Path(home) / RELATIVE
    # No legacy inputs accepted, no overwrite, no copying keys or profile bodies.
    print('Preserve legacy profiles, keys, services and evidence. This creates a separate fresh profile.')
    print('Review the old profile locally with a redacted diff; never upload its contents.')
    print('No services will be started or enabled. Use a NEW runtime key with Tunnels Read + Use only.')
    if input('Type CREATE FRESH RELAYFORGE TUNNEL: ') != 'CREATE FRESH RELAYFORGE TUNNEL':
        raise ValueError('confirmation required')
    config = profile(tunnel_id, str(target / 'runtime-key'))
    # Existing parents must be trusted. mkdir below uses a verified parent fd.
    parent_relative = '.config/relayforge'
    parent = target.parent
    if not parent.is_dir():
        raise ValueError('create private ~/.config/relayforge locally first')
    # Verify all ancestors through no-follow directory descriptors.
    fd = os.open('/', FLAGS | os.O_DIRECTORY)
    try:
        for part in [*Path(home).parts[1:], *parent_relative.split('/')]:
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky):
                raise ValueError('unsafe parent')
        key = getpass.getpass('New runtime key (never a legacy or admin key): ')
        if not key.strip() or '\n' in key or '\x00' in key or len(key) > 16384:
            raise ValueError('invalid key')
        os.mkdir('managed-tunnel', mode=0o700, dir_fd=fd)  # EEXIST is a hard refusal
    finally:
        os.close(fd)
    fd = directory(home)
    try:
        for name, data in [('profile.json', json.dumps(config, indent=2) + '\n'), ('runtime-key', key)]:
            child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(child, 'w') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    finally:
        os.close(fd)
    print('Fresh files created. Review locally; activation requires separate owner authorization.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'setup', 'check', 'run'))
    parser.add_argument('--tunnel-id')
    args = parser.parse_args()
    if os.getuid() == 0:
        raise ValueError('ordinary user required')
    home = pwd.getpwuid(os.getuid()).pw_dir
    if args.action == 'plan':
        print('Preserve ~/.config/tunnel-client and legacy ~/.local/libexec/relayforge unchanged.')
        print('Inventory legacy unit overrides, processes and ownership locally; stop if they conflict.')
        print('New profile: ~/' + RELATIVE + '/profile.json; new key required; no services changed.')
    elif args.action == 'setup':
        setup(home, args.tunnel_id or '')
    else:
        launch(home, args.action == 'check')


if __name__ == '__main__':
    try:
        main()
    except Refused as error:
        print('RelayForge tunnel refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Never echo profile values, key bodies, subprocess arguments or errors.
        print('RelayForge tunnel refused: inspect package integrity and private setup locally.', file=sys.stderr)
        sys.exit(1)
