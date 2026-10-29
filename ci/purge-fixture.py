"""Exercise the actual installed purge tool saved before pacman removal, via PTY."""
import json
import os
from pathlib import Path
import pty
import subprocess

script = '/tmp/installed-user-data.py'
command = ['python3', script, '--file', '.config/relayforge/http-token']
plan = json.loads(subprocess.check_output(command, text=True))
assert plan['applied'] is False
bad = subprocess.run(command + ['--confirm', plan['confirmation']], input='', text=True, capture_output=True)
assert bad.returncode != 0, 'non-terminal confirmation accepted'
master, slave = pty.openpty()
try:
    child = subprocess.Popen(command + ['--confirm', plan['confirmation']], stdin=slave,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    os.write(master, b'PURGE RelayForge user files\n')
    stdout, stderr = child.communicate(timeout=10)
    assert child.returncode == 0, stderr
    assert '"applied": true' in stdout
finally:
    os.close(master)
    os.close(slave)
assert not (Path.home() / '.config/relayforge/http-token').exists()
assert (Path.home() / 'unrelated-evidence').read_text() == 'retained'
assert json.loads(subprocess.check_output(command, text=True))['plan']['files'][0]['absent']
