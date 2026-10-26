"""Start only the installed user unit on a disposable CI user manager."""
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request


def ctl(*args, check=True):
    return subprocess.run(['systemctl', '--user', *args], check=check, capture_output=True, text=True)


subprocess.run(['systemd-analyze', '--user', 'verify',
                '/usr/lib/systemd/user/relayforge-mcp-http.service'], check=True)
assert ctl('is-enabled', 'relayforge-mcp-http.service', check=False).stdout.strip() == 'disabled'
assert ctl('is-active', 'relayforge-mcp-http.service', check=False).returncode != 0
ctl('start', 'relayforge-mcp-http.service')
try:
    pid = int(ctl('show', '-p', 'MainPID', '--value', 'relayforge-mcp-http.service').stdout)
    assert Path(f'/proc/{pid}/exe').resolve() == Path('/usr/bin/relayforge-mcp')
    data = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(100):
        try:
            req = urllib.request.Request('http://127.0.0.1:8765/mcp', data=data,
                                         headers={'Content-Type': 'application/json',
                                                  'Accept': 'application/json, text/event-stream'})
            opener.open(req, timeout=2)
            raise AssertionError('unauthenticated request accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
            break
        except urllib.error.URLError:
            time.sleep(.1)
    else:
        raise AssertionError('installed unit unavailable')
    req.add_header('Authorization', 'Bearer ' + 'a7' * 32)
    with opener.open(req, timeout=3) as reply:
        assert json.load(reply)['result']['tools']
finally:
    ctl('stop', 'relayforge-mcp-http.service')
assert ctl('is-active', 'relayforge-mcp-http.service', check=False).returncode != 0
assert ctl('is-enabled', 'relayforge-mcp-http.service', check=False).stdout.strip() == 'disabled'
