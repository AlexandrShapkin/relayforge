import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import verify


def snapshot(paths):
    return {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}


class IsolationTests(unittest.TestCase):
    def fixture(self, root):
        live = root / 'target/release/relayforge-mcp'
        runtime = root / 'home/.local/libexec/relayforge/runtime/artifacts/fixture/relayforge-mcp'
        for p in [live, runtime]:
            p.parent.mkdir(parents=True)
            p.write_bytes(b'working runtime sentinel')
        return [live, runtime]

    def test_real_release_build_and_default_cargo_config_never_touch_runtime(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            live = self.fixture(root)
            before = snapshot(live)
            (root / '.cargo').mkdir()
            shutil.copyfile(ROOT / '.cargo/config.toml', root / '.cargo/config.toml')
            (root / 'src').mkdir()
            (root / 'src/main.rs').write_text('fn main() {}')
            (root / 'Cargo.toml').write_text('[package]\nname="relayforge-mcp"\nversion="0.0.0"\nedition="2021"\n')
            env = dict(os.environ)
            env.pop('CARGO_TARGET_DIR', None)
            metadata = subprocess.run(['cargo', 'metadata', '--offline', '--no-deps', '--format-version=1'], cwd=root, env=env, capture_output=True, text=True, check=True)
            self.assertEqual(Path(json.loads(metadata.stdout)['target_directory']), root / '.build/cargo')
            for flags in [[], ['--target-dir', str(root / '.build/explicit-release')]]:
                result = subprocess.run(['cargo', 'build', '--release', '--offline', *flags], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(snapshot(live), before)
            self.assertTrue((root / '.build/cargo/release/relayforge-mcp').is_file())

    def test_actual_just_verify_routes_cargo_and_smoke_to_isolated_tree(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            live = self.fixture(root)
            before = snapshot(live)
            (root / 'scripts').mkdir()
            (root / 'bin').mkdir()
            (root / 'deploy').mkdir()
            for name in ['relayforge-hot-activate.sh', 'install-local-recovery.sh']:
                shutil.copyfile(ROOT / 'deploy' / name, root / 'deploy' / name)
            shutil.copyfile(ROOT / 'justfile', root / 'justfile')
            shutil.copyfile(ROOT / 'scripts/verify.py', root / 'scripts/verify.py')
            (root / 'scripts/development_interface.py').write_text('print("fixture docs check")')
            (root / 'scripts/test_fixture.py').write_text('import unittest\nclass FixtureTest(unittest.TestCase):\n def test_fixture(self): self.assertTrue(True)\n')
            # Real just/verify dispatch with a recording Cargo, never a live service.
            cargo = root / 'bin/cargo'
            cargo.write_text('#!/usr/bin/env python3\nimport sys,json,os,pathlib\na=sys.argv[1:]\nt=pathlib.Path(os.environ["CARGO_TARGET_DIR"])\nif a[0]!="fmt": assert a[a.index("--target-dir")+1]==str(t)\nassert str(t).endswith("/.build/verification")\nwith open("cargo-calls.jsonl","a") as f:f.write(json.dumps(a)+"\\n")\nif a[0]=="build":\n (t/"release").mkdir(parents=True)\n (t/"release/relayforge-mcp").write_bytes(b"fixture build")\n')
            cargo.chmod(0o700)
            (root / 'scripts/offline_mcp_smoke.py').write_text('import sys,pathlib\np=pathlib.Path(sys.argv[1]);assert p==pathlib.Path.cwd()/".build/verification/release/relayforge-mcp";assert p.read_bytes()==b"fixture build"\npathlib.Path("smoke-ran").write_text("ok")')
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'], CARGO_TARGET_DIR=str(root / 'target'))
            result = subprocess.run(['just', 'verify'], cwd=root, env=env, capture_output=True, text=True, timeout=40)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(snapshot(live), before)
            self.assertTrue((root / 'smoke-ran').exists())
            self.assertEqual(len((root / 'cargo-calls.jsonl').read_text().splitlines()), 4)

    def test_legacy_activation_is_fail_closed_and_new_workers_do_not_select_cargo(self):
        text = (ROOT / 'deploy/relayforge-hot-activate.sh').read_text()
        self.assertNotIn('cargo build', text)
        self.assertNotIn('systemctl', text)
        result = subprocess.run(['bash', str(ROOT / 'deploy/relayforge-hot-activate.sh'), 'a' * 40], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('REFUSED', result.stderr)
        launcher = (ROOT / 'deploy/relayforge-tunnel-mcp.sh').read_text()
        self.assertNotIn('target/release', launcher)
        worker = (ROOT / 'crates/relayforge-mcp/src/stdio.rs').read_text().split('fn worker_binary()', 1)[1].split('fn call_worker', 1)[0]
        self.assertNotIn('target/release', worker)
        self.assertIn('/proc/', worker)
        build = next(c for c in verify.commands() if c[:2] == ['cargo', 'build'])
        self.assertIn('--target-dir', build)


if __name__ == '__main__':
    unittest.main()
