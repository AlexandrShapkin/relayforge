"""Compiled-in offline Python profile. Only runs inside the existing sandbox."""
import difflib
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
proposal = json.loads(Path('/job/development.json').read_text())
expires = json.loads(Path('/job/development.authority.json').read_text())['expires_at']


def check_deadline():
    if time.time() >= expires:
        raise RuntimeError('task authorization expired')


check_deadline()
root = Path('/tmp/development')
root.mkdir(mode=0o700)
patch = []
for edit in proposal['edits']:
    check_deadline()
    path = root / edit['path']
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(edit['before'])
    assert path.read_text() == edit['before']
    path.write_text(edit['after'])
    patch.extend(difflib.unified_diff(edit['before'].splitlines(keepends=True),
                                    edit['after'].splitlines(keepends=True),
                                    fromfile='a/' + edit['path'],
                                    tofile='b/' + edit['path']))


def run(arguments):
    check_deadline()
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            code = subprocess.run(['/usr/bin/python3', '-I', '-S', *arguments],
                                  cwd=root, stdin=subprocess.DEVNULL,
                                  stdout=out, stderr=err,
                                  timeout=min(15, max(0.001, expires - time.time()))).returncode
        except subprocess.TimeoutExpired:
            code = 124
        streams = []
        for file in [out, err]:
            file.seek(0)
            data = file.read(8193)
            if len(data) > 8192:
                code = 1
            streams.append(data[:8192].decode('utf-8', errors='replace'))
        return {'exit_code': code, 'stdout': streams[0], 'stderr': streams[1]}


build = run(['-m', 'compileall', '-q', 'scripts'])
test = None
if build['exit_code'] == 0 and time.time() < expires:
    test = run(['-c', "import unittest,sys; suite=unittest.defaultTestLoader.discover('scripts'); "
                "assert suite.countTestCases()>0, 'no tests discovered'; "
                "sys.exit(not unittest.TextTestRunner().run(suite).wasSuccessful())"])
unchanged = all((root / e['path']).is_file() and not (root / e['path']).is_symlink()
                and (root / e['path']).read_bytes() == e['after'].encode()
                for e in proposal['edits'])
ok = (build['exit_code'] == 0 and test is not None and test['exit_code'] == 0
      and unchanged and time.time() < expires)
result = {'schema_version': 1, 'base_revision': proposal['base_revision'],
          'repository': proposal['repository'], 'profile': proposal['profile'],
          'python_version': sys.version.split()[0],
          'paths': [e['path'] for e in proposal['edits']], 'build': build, 'test': test,
          'source_unchanged_by_tests': unchanged, 'diff': ''.join(patch), 'ok': ok}
print(json.dumps(result, ensure_ascii=True))
sys.exit(0 if ok else 1)
