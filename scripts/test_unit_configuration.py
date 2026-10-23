#!/usr/bin/env python3
"""Two-unit transaction tests with real files and injected write/reload failures."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('units', Path(__file__).resolve().parents[1] / 'deploy/unit_configuration.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class UnitConfigurationTests(unittest.TestCase):
    def test_roundtrip_and_partial_failures(self):
        for failure in ('none', 'before-first', 'between', 'after-second', 'reload'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                units = [(Path(tmp) / name, {'baseline': (name + '-original\n\n').encode(),
                          'candidate': (name + '-candidate\n').encode()})
                         for name in ('http', 'tunnel')]
                for path, pins in units:
                    path.write_bytes(pins['baseline'])
                    path.chmod(0o644)
                count = 0
                reloads = []
                def write(path, data, mode):
                    nonlocal count
                    count += 1
                    if (failure, count) in [('before-first', 1), ('between', 2)]:
                        raise OSError('injected write failure')
                    temp = path.with_suffix('.tmp')
                    temp.write_bytes(data)
                    temp.chmod(mode)
                    temp.replace(path)
                    if failure == 'after-second' and count == 2:
                        raise OSError('injected post-rename failure')
                def reload():
                    reloads.append(1)
                    if failure == 'reload' and len(reloads) == 1:
                        raise OSError('injected reload failure')
                if failure == 'none':
                    u.install(units, 'candidate', write, reload, lambda: None)
                    for path, pins in units:
                        self.assertEqual(path.read_bytes(), pins['candidate'])
                    u.install(units, 'baseline', write, reload, lambda: self.fail('baseline needs no scaffold'))
                else:
                    with self.assertRaises(OSError):
                        u.install(units, 'candidate', write, reload, lambda: None)
                for path, pins in units:
                    self.assertEqual(path.read_bytes(), pins['baseline'])
                    self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_interrupted_pair_and_recovery_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            units = [(Path(tmp) / name, {'baseline': b'original\n\n', 'candidate': b'new\n'})
                     for name in ('http', 'tunnel')]
            for i, (path, pins) in enumerate(units):
                path.write_bytes(pins['candidate' if i == 0 else 'baseline'])
                path.chmod(0o644)
            def write(path, data, mode):
                path.write_bytes(data)
            u.install(units, 'baseline', write, lambda: None, lambda: self.fail())
            for path, pins in units:
                self.assertEqual(path.read_bytes(), pins['baseline'])
            units[1][0].write_bytes(b'unknown')
            with self.assertRaises(RuntimeError):
                u.install(units, 'candidate', lambda *args: self.fail(), lambda: self.fail(), lambda: None)
            self.assertEqual(units[0][0].read_bytes(), b'original\n\n')

    def test_recovery_continues_after_one_restore_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            units = [(Path(tmp) / name, {'baseline': b'old', 'candidate': b'new'})
                     for name in ('http', 'tunnel')]
            for path, pins in units:
                path.write_bytes(pins['candidate'])
                path.chmod(0o644)
            def write(path, data, mode):
                if path == units[0][0]:
                    raise OSError('HTTP filesystem unavailable')
                path.write_bytes(data)
            reloads = []
            with self.assertRaises(OSError):
                u.install(units, 'baseline', write, lambda: reloads.append(1), lambda: self.fail())
            self.assertEqual(units[1][0].read_bytes(), b'old')
            self.assertEqual(reloads, [1])
            u.install(units, 'baseline', lambda p, data, mode: p.write_bytes(data),
                      lambda: None, lambda: self.fail())
            self.assertEqual(units[0][0].read_bytes(), b'old')

    def test_tunnel_preserves_hardening_and_polling(self):
        unit = (Path(__file__).resolve().parents[1] / 'deploy/systemd/relayforge-tunnel.service').read_text()
        for line in ['ProtectHome=read-only', 'ProtectSystem=full', 'PrivateTmp=true',
                     'NoNewPrivileges=true', 'UMask=0077',
                     'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
                     'ReadWritePaths=%t/relayforge-tunnel %h/.local/state/relayforge',
                     'ConditionPathExists=%h/.config/relayforge/tunnel/runtime-key',
                     'BindReadOnlyPaths=%h/.local/share/relayforge/http-home:/home %h:%h']:
            self.assertIn(line + '\n', unit)
        for option in ['--control-plane.poll-timeout 6s', '--control-plane.initial-poll-timeout 6s',
                       '--control-plane.poll-deadline-guardrail 5s']:
            self.assertIn(option, unit)
        self.assertEqual(unit.count('BindReadOnlyPaths='), 1)
        self.assertEqual(unit.count('ReadWritePaths='), 1)

    def test_prerequisites_before_any_write(self):
        def missing():
            raise RuntimeError('missing scaffold/audit')
        with self.assertRaises(RuntimeError):
            u.install([], 'candidate', lambda *args: self.fail(), lambda: self.fail(), missing)


if __name__ == '__main__':
    unittest.main()
