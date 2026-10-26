#!/usr/bin/python3
"""Remove explicitly named ordinary user files only; default is a read-only plan.

No recursive deletion, directories, runtime images, selectors, recovery receipts,
service units or evidence. Stop services separately from an attended terminal.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

# Everything else (including artifact reports and recovery state) is retained.
ALLOWLIST = ('.config/relayforge/http-token', '.config/relayforge/artifact-roots.json')
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def parent_fd(home, relative):
    fd = os.open('/', FLAGS | os.O_DIRECTORY)
    try:
        for part in Path(home).parts[1:]:
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            sticky_tmp = part == 'tmp' and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.getuid()) or (info.st_mode & 0o022 and not sticky_tmp):
                raise ValueError('unsafe HOME ancestor')
        parts = relative.split('/')[:-1]
        for part in [None, *parts]:
            if part is not None:
                child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise ValueError('unsafe parent ownership/mode')
        return fd
    except BaseException:
        os.close(fd)
        raise


def purge(home, names, confirmation=None):
    if os.getuid() == 0 or not Path(home).is_absolute():
        raise ValueError('ordinary user with absolute HOME required')
    if not names or len(names) != len(set(names)) or not set(names) <= set(ALLOWLIST):
        raise ValueError('explicit unique allowlisted file names required')
    opened, records = [], []
    try:
        for name in sorted(names):
            try:
                fd = parent_fd(home, name)
            except FileNotFoundError:
                records.append({'path': name, 'absent': True})
                continue
            opened.append((fd, name))
            try:
                info = os.stat(name.split('/')[-1], dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                records.append({'path': name, 'absent': True})
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise ValueError('unsafe file type/ownership/mode/links')
            # Identity only: never read or print credential contents or hashes.
            records.append({'path': name, 'device': info.st_dev, 'inode': info.st_ino,
                            'mtime_ns': info.st_mtime_ns, 'size': info.st_size})
        plan = {'home': str(home), 'files': records}
        token = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
        if confirmation is not None:
            if confirmation != token:
                raise ValueError('plan changed or confirmation mismatch')
            if not os.isatty(0) or input('Type PURGE RelayForge user files: ') != 'PURGE RelayForge user files':
                raise ValueError('physical terminal confirmation required')
            for fd, name in opened:
                record = next(r for r in records if r['path'] == name)
                if record.get('absent'):
                    continue
                info = os.stat(name.split('/')[-1], dir_fd=fd, follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or info.st_nlink != 1 or info.st_mode & 0o077):
                    raise ValueError('file security metadata changed')
                if (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size) != tuple(
                        record[key] for key in ('device', 'inode', 'mtime_ns', 'size')):
                    raise ValueError('file changed; stop and replan')
                os.unlink(name.split('/')[-1], dir_fd=fd)
                os.fsync(fd)
        return {'plan': plan, 'confirmation': token, 'applied': confirmation is not None}
    finally:
        for fd, _ in opened:
            os.close(fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', action='append', required=True, choices=ALLOWLIST)
    parser.add_argument('--confirm', help='digest from unchanged dry-run; also prompts on a local terminal')
    args = parser.parse_args()
    try:
        print(json.dumps(purge(os.environ['HOME'], args.file, args.confirm), sort_keys=True))
    except (OSError, ValueError, EOFError):
        raise SystemExit('purge refused; preserve files and review locally') from None
