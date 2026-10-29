"""Package trust-boundary regressions with synthetic executable bytes only."""
import gzip
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import source_package as p


class SourcePackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        binary = self.root / 'fixture'
        binary.write_bytes(b'synthetic MCP executable; never executed')
        self.commit = 'a' * 40
        def git(args, **kwargs):
            if args[1] == 'rev-parse':
                return self.commit + '\n'
            return (p.ROOT / args[2].split(':', 1)[1]).read_bytes()
        with patch.object(p.subprocess, 'check_output', side_effect=git):
            self.archive = p.build(binary, self.root / 'output')

    def rewrite(self, change, reseal=False):
        with tarfile.open(self.archive) as tar:
            entries = {m.name: [m, tar.extractfile(m).read()] for m in tar.getmembers()}
        change(entries)
        if reseal:
            entries['seal.json'][1] = p.encoded({name: {'sha256': p.digest(data), 'mode': info.mode}
                for name, (info, data) in entries.items() if name != 'seal.json'})
        with tarfile.open(self.archive, 'w:gz') as tar:
            for info, data in entries.values():
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

    def test_valid_and_wrong_commit(self):
        p.verify(self.archive, self.commit)
        for commit in ['a' * 7, 'b' * 40]:
            with self.assertRaises(ValueError):
                p.verify(self.archive, commit)

    def test_support_copies_and_seal_match_tracked_source(self):
        # Portable counterpart of R3's exact support-copy and seal checks.
        # This fixture is built from tracked source and synthetic binary bytes.
        with tarfile.open(self.archive) as tar:
            entries = {m.name: (m, tar.extractfile(m).read()) for m in tar}
        self.assertEqual(set(entries), set(p.SOURCES) | {
            'bin/relayforge-mcp', 'manifest.json', 'package.json', 'seal.json'})
        for name in p.SOURCES:
            with self.subTest(source=name):
                self.assertEqual(entries[name][1], (p.ROOT / name).read_bytes())
        seal = json.loads(entries['seal.json'][1])
        self.assertEqual(set(seal), set(entries) - {'seal.json'})
        for name, (info, body) in entries.items():
            with self.subTest(member=name):
                mode = 0o500 if name.startswith('bin/') else 0o400
                self.assertEqual(info.mode, mode)
                if name != 'seal.json':
                    self.assertEqual(seal[name], {'sha256': p.digest(body), 'mode': mode})

    def test_support_code_tampering_fails_seal(self):
        original = self.archive.read_bytes()
        for name in ('deploy/attended_upgrade.py', 'deploy/attended_activation.py',
                     'deploy/activation_transaction.py', 'deploy/runtime_artifact.py'):
            with self.subTest(source=name):
                self.archive.write_bytes(original)
                self.rewrite(lambda e: e[name].__setitem__(1, b'changed support code'))
                with self.assertRaisesRegex(ValueError, 'seal'):
                    p.verify(self.archive, self.commit)

    def test_private_receipt_slots_cannot_enter_source_bundle(self):
        original = self.archive.read_bytes()
        for name in ('rollback-receipt.json', 'independent-evidence.json'):
            with self.subTest(receipt=name):
                self.archive.write_bytes(original)
                def add(entries):
                    info = tarfile.TarInfo(name)
                    info.mode = 0o400
                    entries[name] = [info, b'{}']
                self.rewrite(add, reseal=True)
                with self.assertRaisesRegex(ValueError, 'inventory'):
                    p.verify(self.archive, self.commit)

    def test_verify_bounds_unpacked_bytes(self):
        # A low test-only limit exercises the cumulative bound without a
        # large allocation or a compressed-bomb fixture.
        with patch.object(p, 'MAX_UNPACKED_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'unpacked size'):
                p.verify(self.archive, self.commit)

    def test_verify_does_not_enumerate_unbounded_headers(self):
        with patch.object(tarfile.TarFile, 'getmembers',
                          side_effect=AssertionError('unbounded header enumeration')):
            p.verify(self.archive, self.commit)

    def test_rejects_oversized_extension_headers_before_reading_body(self):
        # No large allocation: a declared 1 GiB extension has no payload.
        # tarfile's ordinary iterator would try to read that payload first.
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind):
                header = tarfile.TarInfo('extension')
                header.type = kind
                header.size = 1 << 30
                with gzip.open(self.archive, 'wb') as stream:
                    stream.write(header.tobuf())
                with self.assertRaisesRegex(ValueError, 'unsafe package member'):
                    p.verify(self.archive, self.commit)

    def test_rejects_repeated_extension_headers(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind):
                header = tarfile.TarInfo('extension')
                header.type = kind
                header.size = 0
                with gzip.open(self.archive, 'wb') as stream:
                    stream.write(header.tobuf() * 64 + bytes(1024))
                with self.assertRaisesRegex(ValueError, 'unsafe package member'):
                    p.verify(self.archive, self.commit)

    def test_changed_bytes_fail_seal(self):
        self.rewrite(lambda e: e['bin/relayforge-mcp'].__setitem__(1, b'changed'))
        with self.assertRaisesRegex(ValueError, 'seal'):
            p.verify(self.archive, self.commit)

    def test_resealed_invalid_manifest_is_rejected(self):
        self.rewrite(lambda e: e['manifest.json'].__setitem__(1, p.encoded({
            'schema_version': 2, 'commit': self.commit, 'binary': 'relayforge-mcp',
            'sha256': p.digest(e['bin/relayforge-mcp'][1])})), reseal=True)
        with self.assertRaisesRegex(ValueError, 'manifest'):
            p.verify(self.archive, self.commit)

    def test_resealed_role_and_approval_changes_are_rejected(self):
        def change(entries):
            value = json.loads(entries['package.json'][1])
            value['roles']['worker']['argv'] = ['--http']
            value['activation_allowed'] = True
            entries['package.json'][1] = p.encoded(value)
        self.rewrite(change, reseal=True)
        with self.assertRaisesRegex(ValueError, 'roles/authority'):
            p.verify(self.archive, self.commit)

    def test_links_paths_extra_files_and_modes_fail_closed(self):
        original = self.archive.read_bytes()
        def link(e):
            e['bin/relayforge-mcp'][0].type = tarfile.SYMTYPE
            e['bin/relayforge-mcp'][0].linkname = '/outside'
        def escape(e):
            e['manifest.json'][0].name = '../manifest.json'
        def extra(e):
            e['credential'] = [tarfile.TarInfo('credential'), b'synthetic forbidden extra']
        def mode(e):
            e['package.json'][0].mode = 0o600
        for change in [link, escape, extra, mode]:
            with self.subTest(change=change.__name__):
                self.archive.write_bytes(original)
                self.rewrite(change)
                with self.assertRaises(ValueError):
                    p.verify(self.archive, self.commit)
