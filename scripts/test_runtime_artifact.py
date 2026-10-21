import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import runtime_artifact as runtime


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def artifact(self, name, commit, data):
        binary = self.root / name
        binary.write_bytes(data)
        binary.chmod(0o500)
        digest = hashlib.sha256(data).hexdigest()
        manifest = binary.with_suffix('.json')
        manifest.write_text(json.dumps({"schema_version": 1, "commit": commit, "sha256": digest, "binary": "relayforge-mcp"}))
        return binary, manifest, commit, digest

    def test_digest_or_full_commit_mismatch_never_produces_a_plan(self):
        args = self.artifact('candidate', 'a' * 40, b'candidate')
        for changed in [(*args[:2], 'b' * 40, args[3]), (*args[:3], '0' * 64), (*args[:2], 'a' * 7, args[3])]:
            with self.assertRaises(runtime.ArtifactError):
                runtime.verify(*changed)
        self.assertEqual(args[0].read_bytes(), b'candidate')

    def test_missing_or_unverified_rollback_is_refused(self):
        candidate = self.artifact('candidate', 'a' * 40, b'candidate')
        rc = runtime.main(['plan', '--binary', str(candidate[0]), '--manifest', str(candidate[1]),
                           '--commit', candidate[2], '--sha256', candidate[3]])
        self.assertEqual(rc, 2)
        old = self.artifact('mcp-hot-last-good', 'b' * 40, b'old')
        with self.assertRaises(runtime.ArtifactError):
            runtime.activation_plan(runtime.verify(*candidate), runtime.verify(*old), self.root / 'missing-receipt')
        receipt = self.root / 'receipt.json'
        receipt.write_text(json.dumps({'commit': old[2], 'sha256': old[3], 'restricted_worker_ok': True, 'live_health_ok': False}))
        with self.assertRaises(runtime.ArtifactError):
            runtime.activation_plan(runtime.verify(*candidate), runtime.verify(*old), receipt)

    def test_verified_plan_is_read_only_and_requires_separate_authority(self):
        candidate = self.artifact('candidate', 'a' * 40, b'candidate')
        old = self.artifact('rollback', 'b' * 40, b'old')
        receipt = self.root / 'receipt.json'
        receipt.write_text(json.dumps({'commit': old[2], 'sha256': old[3], 'restricted_worker_ok': True, 'live_health_ok': True}))
        before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()}
        plan = runtime.activation_plan(runtime.verify(*candidate), runtime.verify(*old), receipt)
        self.assertTrue(plan['operator_approval_required'])
        self.assertEqual(plan['actions_performed'], [])
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.iterdir()})
        self.assertFalse((self.root / 'current').exists())

    def test_symlinked_artifacts_and_redirected_parent_are_rejected(self):
        args = self.artifact('candidate', 'a' * 40, b'candidate')
        alias = self.root / 'alias'
        alias.symlink_to(args[0])
        with self.assertRaises(runtime.ArtifactError):
            runtime.verify(alias, *args[1:])
        directory = self.root / 'directory-link'
        directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(runtime.ArtifactError):
            runtime.verify(directory / 'candidate', *args[1:])


if __name__ == '__main__':
    unittest.main()
