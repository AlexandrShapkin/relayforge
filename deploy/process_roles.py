"""Fail-closed observations; never starts a worker or infers one from HTTP."""
import hashlib
import os
import stat
from pathlib import Path


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


METADATA_LIMIT = 64 * 1024
EXECUTABLE_LIMIT = 128 * 1024 * 1024


def snapshot(pid, hash_exe=True, proc_root=Path('/proc')):
    """Pin proc directory; bound metadata and stream only requested identities.

    exe is the kernel procfs link, deliberately followed relative to the pinned
    directory. Its inode/size/timestamps and process metadata must stay stable.
    proc_root is injectable for deterministic procfs fixtures, never operator input.
    """
    require(type(pid) is int and pid > 0, 'invalid process PID')
    fd = os.open(proc_root / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        def read(name):
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                data = os.read(child, METADATA_LIMIT + 1)
                require(len(data) <= METADATA_LIMIT, 'process metadata too large')
                return data
            finally:
                os.close(child)

        def metadata():
            raw = read('stat')
            fields = raw[raw.rindex(b')')+2:].split()
            require(fields[0] not in (b'Z', b'X'), 'process exited')
            exe = os.stat('exe', dir_fd=fd)
            return dict(ppid=int(fields[1]), start=int(fields[19]),
                        uid=os.fstat(fd).st_uid, argv=read('cmdline').split(b'\0'),
                        exe=os.readlink('exe', dir_fd=fd),
                        identity=(exe.st_dev, exe.st_ino, exe.st_size,
                                  exe.st_mtime_ns, exe.st_ctime_ns))

        before = metadata()
        if hash_exe:
            child = os.open('exe', os.O_RDONLY, dir_fd=fd)
            try:
                st = os.fstat(child)
                require((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                         st.st_ctime_ns) == before['identity'], 'executable identity raced')
                require(stat.S_ISREG(st.st_mode), 'required executable not regular')
                require(st.st_size <= EXECUTABLE_LIMIT, 'required executable too large')
                digest = hashlib.sha256()
                total = 0
                while chunk := os.read(child, 1024 * 1024):
                    total += len(chunk)
                    require(total <= EXECUTABLE_LIMIT, 'required executable too large')
                    digest.update(chunk)
                require(total == st.st_size, 'executable size raced')
                after = os.fstat(child)
                require((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                        'executable identity raced')
            finally:
                os.close(child)
        require(before == metadata(), 'process identity raced')
        if hash_exe:
            before['sha256'] = digest.hexdigest()
        return before
    finally:
        os.close(fd)


def observe_roles(members, expected, tunnel_hash, uid, sample=snapshot):
    """Require simultaneous, stable cgroup/identity/ancestry evidence.

    Return only actual restricted worker PIDs. Timeout intermediaries are allowed
    but must be stable, same-owner members of this tunnel cgroup. A disappeared
    process or any changed snapshot invalidates the observation, never acceptance.
    """
    try:
        main, group, pids = members()
        require(main in pids, 'tunnel main absent from cgroup')
        observed = {pid: sample(pid, hash_exe=False) for pid in pids}
        require(all(p['uid'] == uid for p in observed.values()), 'process owner mismatch')
        modes = {b'--readonly-stdio', b'--readonly-worker'}
        candidates = {pid for pid, p in observed.items()
                      if modes.intersection(p['argv'][1:])
                      or Path(p['exe'].removesuffix(' (deleted)')).name == 'relayforge-mcp'}
        identities = {observed[pid]['identity'] for pid in candidates}
        candidates.update(pid for pid, p in observed.items() if p['identity'] in identities)
        for pid in candidates | {main}:
            hashed = sample(pid, hash_exe=True)
            digest = hashed.pop('sha256')
            require(hashed == observed[pid], 'process identity raced')
            observed[pid]['sha256'] = digest
        require(observed[main]['sha256'] == tunnel_hash, 'tunnel hash mismatch')
        parents, workers = [], []
        for pid, p in observed.items():
            if pid == main or pid not in candidates:
                continue
            args = p['argv'][1:]
            if p['sha256'] == expected:
                require(args in ([b'--readonly-stdio', b''], [b'--readonly-worker', b'']), 'MCP argv mismatch')
                (parents if args == [b'--readonly-stdio', b''] else workers).append(pid)
            else:
                raise RuntimeError('MCP hash mismatch')
        require(len(parents) == 1, 'missing or ambiguous persistent parent')
        parent = parents[0]
        def descends(pid, ancestor):
            seen = set()
            while pid in observed and pid not in seen:
                if pid == ancestor:
                    return True
                seen.add(pid)
                pid = observed[pid]['ppid']
            return False
        require(descends(parent, main), 'parent outside tunnel ancestry')
        require(workers, 'missing independent worker evidence')
        require(all(descends(pid, parent) for pid in workers), 'worker outside parent ancestry')
        require(members() == (main, group, pids), 'cgroup identity raced')
        require(all(sample(pid, hash_exe='sha256' in old) == old for pid, old in observed.items()), 'process identity raced')
        require(members() == (main, group, pids), 'cgroup identity raced')
        return sorted(workers)
    except (OSError, ValueError, IndexError) as error:
        raise RuntimeError('process evidence unavailable or raced') from error
