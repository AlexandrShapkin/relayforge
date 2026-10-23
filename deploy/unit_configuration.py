"""Exact-byte, recoverable configuration changes for an attended activation.

No service is restarted here. Callers supply independently pinned bytes and a
reload callback; this module confers no installation authority.
"""
import os
from pathlib import Path
import stat


def verify(path, allowed):
    path = Path(path)
    meta = path.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
            or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != 0o644
            or path.read_bytes() not in allowed):
        raise RuntimeError('unexpected unit configuration')


def install(units, state, atomic_file, reload, prerequisites):
    """Validate the whole pair first; compensate each file on partial failure.

    An interrupted process may leave either pinned state on disk. Baseline
    recovery needs no candidate prerequisites and attempts every unit and reload
    even if another restoration fails. Unknown bytes are never overwritten.
    """
    if state not in ('baseline', 'candidate'):
        raise ValueError('unknown unit state')
    if state == 'candidate':
        prerequisites()
    for path, pins in units:
        verify(path, pins.values())
    try:
        for path, pins in units:
            if Path(path).read_bytes() != pins[state]:
                atomic_file(path, pins[state], 0o644)
        reload()
        for path, pins in units:
            verify(path, [pins[state]])
    except BaseException:
        # Includes interruption after rename or a failed daemon-reload. Keep
        # attempting restoration independently; the caller reports failure and
        # can retry this operation using the two exact pinned states.
        for path, pins in units:
            try:
                verify(path, pins.values())
                if Path(path).read_bytes() != pins['baseline']:
                    atomic_file(path, pins['baseline'], 0o644)
            except BaseException:
                pass
        try:
            reload()
        except BaseException:
            pass
        raise
