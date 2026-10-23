"""Durable exact-state filesystem transactions for attended activation.

Callers define fixed paths and approved bytes. This module never authorizes an
activation or invokes a service. Journal files are private and survive SIGKILL;
rollback accepts only the recorded before/after states and never guesses.
"""
import base64
import json
import os
from pathlib import Path
import stat
import uuid


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def ancestors(path):
    """Validate real components; unmapped ownership is never trusted."""
    path = Path(path)
    if not path.is_absolute():
        raise RuntimeError('absolute path required')
    for item in reversed([path, *path.parents]):
        meta = item.lstat()
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, os.getuid())
                or meta.st_mode & 0o022 and not (item == Path('/tmp') and meta.st_uid == 0
                                               and meta.st_mode & stat.S_ISVTX)):
            raise RuntimeError('unsafe directory component')


def directory(path, create=False, private=True):
    path = Path(path)
    missing = []
    cursor = path
    while not cursor.exists() and not cursor.is_symlink():
        missing.append(cursor)
        cursor = cursor.parent
    ancestors(cursor)
    if not os.access(cursor, os.W_OK | os.X_OK) or os.statvfs(cursor).f_flag & os.ST_RDONLY:
        raise RuntimeError('directory is not writable')
    if create:
        for item in reversed(missing):
            item.mkdir(mode=0o700)
            sync(item.parent)
    if not missing or create:
        meta = path.lstat()
        if meta.st_uid != os.getuid() or (private and stat.S_IMODE(meta.st_mode) != 0o700):
            raise RuntimeError('private directory required')
    return [str(p) for p in reversed(missing)]


def regular(path, mode=0o600, limit=None):
    ancestors(Path(path).parent)
    meta = Path(path).lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid()
            or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != mode
            or limit is not None and meta.st_size > limit):
        raise RuntimeError('unsafe regular file')


def private_file(path, create=False, limit=None):
    path = Path(path)
    missing = directory(path.parent, create)
    if path.exists() or path.is_symlink():
        regular(path, limit=limit)
    elif create:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        sync(path.parent)
    else:
        missing.append(str(path))
    return missing


def state(path):
    path = Path(path)
    ancestors(path.parent)
    try:
        meta = path.lstat()
    except FileNotFoundError:
        return None
    if meta.st_uid != os.getuid():
        raise RuntimeError('wrong object owner')
    if stat.S_ISLNK(meta.st_mode):
        return {'link': os.readlink(path)}
    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_mode & 0o022:
        raise RuntimeError('unsafe transaction object')
    if meta.st_size > 1024 * 1024:
        raise RuntimeError('transaction object too large')
    return {'data': base64.b64encode(path.read_bytes()).decode(),
            'mode': stat.S_IMODE(meta.st_mode)}


def file_state(data, mode):
    return {'data': base64.b64encode(data).decode(), 'mode': mode}


def write(path, value, temporary):
    """Atomic rename plus directory fsync; never overwrite a temporary file."""
    path, temporary = Path(path), Path(temporary)
    ancestors(path.parent)
    if value is None:
        path.unlink(missing_ok=True)
        sync(path.parent)
        return
    if 'link' in value:
        os.symlink(value['link'], temporary)
    else:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     value['mode'])
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), value['mode'])
            stream.write(base64.b64decode(value['data'], validate=True))
            stream.flush()
            os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync(path.parent)


class Transaction:
    def __init__(self, journal, targets, create=False, metadata=None, expected_before=None):
        self.path = Path(journal)
        self.targets = {str(Path(p)): value for p, value in targets.items()}
        if create:
            directory(self.path.parent, True)
            if self.path.exists() or self.path.is_symlink():
                raise RuntimeError('journal already exists')
            self.doc = {'version': 1, 'id': uuid.uuid4().hex, 'status': 'pending',
                        'targets': {p: {'before': state(p), 'after': value}
                                    for p, value in self.targets.items()}}
            if expected_before is not None:
                for path, value in expected_before.items():
                    if self.doc['targets'][str(path)]['before'] != value:
                        raise RuntimeError('target changed during planning')
            if metadata:
                if set(metadata) - {'id', 'created', 'deadline', 'physical_owner_approved'}:
                    raise ValueError('unknown journal metadata')
                self.doc.update(metadata)
            self.save(initial=True)
        else:
            regular(self.path)
            self.doc = json.loads(self.path.read_text())
            if (self.doc.get('version') != 1 or not isinstance(self.doc.get('id'), str)
                    or len(self.doc['id']) != 32
                    or any(c not in '0123456789abcdef' for c in self.doc['id'])
                    or {p: v['after'] for p, v in self.doc['targets'].items()} != self.targets):
                raise RuntimeError('journal does not match fixed activation plan')

    def save(self, initial=False):
        data = (json.dumps(self.doc, sort_keys=True, indent=2) + '\n').encode()
        if initial:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            sync(self.path.parent)
        else:
            # A failed/partial save is retained as evidence. A fresh exclusive
            # temporary lets recovery progress using the durable old snapshot.
            temp = self.path.with_name(self.path.name + '.next-' + uuid.uuid4().hex)
            write(self.path, file_state(data, 0o600), temp)

    def temporary(self, path):
        return Path(path).with_name('.relayforge-' + self.doc['id'] + '-' + Path(path).name)

    def apply(self, path):
        path = str(path)
        row = self.doc['targets'][path]
        observed = state(path)
        if observed not in (row['before'], row['after']):
            raise RuntimeError('transaction target changed')
        if observed != row['after']:
            write(path, row['after'], self.temporary(path))

    def rollback(self, force=False):
        if self.doc['status'] == 'committed' and not force:
            return
        failures = []
        for path, row in self.doc['targets'].items():
            try:
                # Interrupted apply/restore temporaries, even incomplete ones,
                # are retained untouched. They never gate restoration of a target
                # whose exact before/after bytes are independently known.
                observed = state(path)
                if observed not in (row['before'], row['after']):
                    raise RuntimeError('rollback target changed')
                if observed != row['before']:
                    restore = self.temporary(path).with_name(
                        self.temporary(path).name + '-restore-' + uuid.uuid4().hex)
                    write(path, row['before'], restore)
            except (OSError, RuntimeError) as error:
                failures.append(type(error).__name__)
        if failures:
            raise RuntimeError('incomplete rollback: ' + ','.join(failures))

    def commit(self):
        for path, row in self.doc['targets'].items():
            if state(path) != row['after']:
                raise RuntimeError('commit target changed')
        self.doc['status'] = 'committed'
        self.save()
