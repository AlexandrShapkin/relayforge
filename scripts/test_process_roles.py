import copy
import sys
import unittest
import hashlib
import os
import tempfile
from unittest.mock import patch
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'deploy'))
from process_roles import observe_roles, snapshot, METADATA_LIMIT

class Roles(unittest.TestCase):
    def setUp(self):
        def proc(ppid, arg, digest='mcp'):
            return dict(ppid=ppid, start=10, uid=1000,
                        argv=[b'program', arg, b''], sha256=digest, exe='program', identity=(digest,))
        self.ps = {1: proc(0,b'client','tunnel'), 2: proc(1,b'--readonly-stdio'),
                   3: proc(2,b'timeout','timeout'), 4: proc(3,b'--readonly-worker')}
    def sample(self, pid, hash_exe=True):
        p = copy.deepcopy(self.ps[pid])
        if not hash_exe:
            p.pop('sha256')
        return p
    def check(self, members=None, sample=None):
        return observe_roles(members or (lambda:(1,'/user.slice/test',set(self.ps))),
                             'mcp','tunnel',1000,sample or self.sample)
    def test_valid_separate_roles_with_timeout(self):
        self.assertEqual(self.check(),[4])
    def test_ambiguous_parent_and_cyclic_ancestry(self):
        self.ps[5] = copy.deepcopy(self.ps[2])
        with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
            self.check()
        del self.ps[5]
        self.ps[2]['ppid'] = 3
        with self.assertRaisesRegex(RuntimeError, 'ancestry'):
            self.check()

    def test_conflicting_named_mcp(self):
        self.ps[5] = dict(ppid=1, start=10, uid=1000, argv=[b'p', b'--http', b''],
                          sha256='wrong', exe='/bin/relayforge-mcp', identity=('other',))
        with self.assertRaisesRegex(RuntimeError, 'hash mismatch'):
            self.check()

    def test_same_executable_wrong_mode(self):
        self.ps[5] = copy.deepcopy(self.ps[2])
        self.ps[5]['argv'] = [b'p', b'--http', b'']
        with self.assertRaisesRegex(RuntimeError, 'argv mismatch'):
            self.check()

    def test_direct_worker(self):
        self.ps[4]['ppid']=2
        self.assertEqual(self.check(),[4])
    def test_wrong_argv_owner_hash(self):
        original=copy.deepcopy(self.ps)
        for pid,key,value in [(2,'argv',[b'p',b'--readonly-worker',b'']),
                              (4,'argv',[b'p',b'--readonly-worker',b'extra',b'']),
                              (2,'uid',0),(4,'uid',0),(1,'sha256','bad'),
                              (2,'sha256','bad'),(4,'sha256','bad')]:
            with self.subTest(pid=pid,key=key):
                self.ps=copy.deepcopy(original);self.ps[pid][key]=value
                with self.assertRaises(RuntimeError):self.check()
    def test_parent_and_http_never_worker_evidence(self):
        del self.ps[4]
        with self.assertRaisesRegex(RuntimeError,'missing independent worker'):self.check()
    def test_wrong_worker_ancestry(self):
        self.ps[4]['ppid']=1
        with self.assertRaisesRegex(RuntimeError,'ancestry'):self.check()
    def test_identity_races(self):
        for key,value in [('start',11),('ppid',1),('sha256','bad'),('uid',0),('argv',[])]:
            calls={}
            def sample(pid, hash_exe=True):
                calls[pid]=calls.get(pid,0)+1
                p=self.sample(pid, hash_exe)
                if pid==4 and calls[pid]>(2 if key == 'sha256' else 1):p[key]=value
                return p
            with self.subTest(key=key),self.assertRaisesRegex(RuntimeError,'raced'):self.check(sample=sample)
    def test_disappearing_process(self):
        def sample(pid, hash_exe=True):raise FileNotFoundError()
        with self.assertRaisesRegex(RuntimeError,'unavailable or raced'):self.check(sample=sample)
    def test_membership_main_or_group_race(self):
        for second in [(9,'/user.slice/test',set(self.ps)),(1,'/user.slice/other',set(self.ps)),(1,'/user.slice/test',{1,2,3})]:
            calls=[]
            def members():
                calls.append(1)
                return (1,'/user.slice/test',set(self.ps)) if len(calls)==1 else second
            with self.subTest(second=second),self.assertRaisesRegex(RuntimeError,'raced'):self.check(members=members)

class ProcFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ps = {}
        for pid, ppid, mode, name, body in [
                (1, 0, b'client', 'tunnel-client', b'tunnel'),
                (2, 1, b'--readonly-stdio', 'relayforge-mcp', b'mcp'),
                (3, 2, b'--readonly-worker', 'relayforge-mcp', b'mcp'),
                (4, 1, b'other', 'codex', b'')]:
            directory = self.root / str(pid)
            directory.mkdir()
            (directory / 'stat').write_bytes(
                str(pid).encode() + b' (name with ) spaces) S ' +
                str(ppid).encode() + b' 0' * 17 + b' 123 0')
            (directory / 'cmdline').write_bytes(name.encode() + b'\0' + mode + b'\0')
            binary = self.root / (name + str(pid))
            binary.write_bytes(body)
            (directory / 'exe').symlink_to(binary)
            self.ps[pid] = directory
        # Sparse, no 276 MiB allocation/read. Opening it for content is forbidden.
        self.large = self.root / 'codex4'
        with self.large.open('r+b') as stream:
            stream.truncate(276 * 1024 * 1024)

    def sample(self, pid, hash_exe=True):
        return snapshot(pid, hash_exe=hash_exe, proc_root=self.root)

    def test_large_unrelated_body_never_opened(self):
        real_open = os.open
        def guarded(path, flags, *args, **kwargs):
            if path == 'exe':
                directory = Path(os.readlink('/proc/self/fd/' + str(kwargs['dir_fd'])))
                self.assertNotEqual(directory, self.ps[4], 'unrelated executable opened')
            return real_open(path, flags, *args, **kwargs)
        with patch('process_roles.os.open', side_effect=guarded):
            self.assertEqual(observe_roles(lambda: (1, 'fixture', set(self.ps)),
                hashlib.sha256(b'mcp').hexdigest(), hashlib.sha256(b'tunnel').hexdigest(),
                os.getuid(), self.sample), [3])

    def test_metadata_bound(self):
        (self.ps[4] / 'cmdline').write_bytes(b'x' * (METADATA_LIMIT + 1))
        with self.assertRaisesRegex(RuntimeError, 'metadata too large'):
            self.sample(4, False)

    def test_required_executable_bound(self):
        with self.assertRaisesRegex(RuntimeError, 'required executable too large'):
            self.sample(4)

    def test_streamed_hash(self):
        self.assertEqual(self.sample(3)['sha256'], hashlib.sha256(b'mcp').hexdigest())

    def test_argv_change_during_hash(self):
        real_read = os.read
        changed = []
        def racing(fd, count):
            data = real_read(fd, count)
            if count == 1024 * 1024 and not changed:
                changed.append(True)
                (self.ps[3] / 'cmdline').write_bytes(b'changed\0')
            return data
        with patch('process_roles.os.read', side_effect=racing):
            with self.assertRaisesRegex(RuntimeError, 'raced'):
                self.sample(3)

    def test_executable_swap_during_hash(self):
        real_read = os.read
        changed = []
        replacement = self.root / 'replacement'
        replacement.write_bytes(b'mcp')
        def racing(fd, count):
            data = real_read(fd, count)
            if count == 1024 * 1024 and not changed:
                changed.append(True)
                (self.ps[3] / 'exe').unlink()
                (self.ps[3] / 'exe').symlink_to(replacement)
            return data
        with patch('process_roles.os.read', side_effect=racing):
            with self.assertRaisesRegex(RuntimeError, 'raced'):
                self.sample(3)

    def test_streaming_multiple_chunks(self):
        data = b'x' * (2 * 1024 * 1024 + 17)
        (self.ps[3] / 'exe').resolve().write_bytes(data)
        self.assertEqual(self.sample(3)['sha256'], hashlib.sha256(data).hexdigest())

if __name__=='__main__':unittest.main()
