#!/usr/bin/env python3
"""Both service templates preserve unrelated hardening and tunnel contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class UnitConfigurationTests(unittest.TestCase):
    def test_real_home_access_and_unrelated_hardening(self):
        for name in ['relayforge-mcp-http.service', 'relayforge-tunnel.service']:
            text = (ROOT / 'deploy/systemd' / name).read_text()
            for line in ['ProtectHome=false', 'ProtectSystem=full', 'PrivateTmp=true',
                         'NoNewPrivileges=true', 'UMask=0077']:
                self.assertIn(line + '\n', text)
            self.assertNotIn('BindReadOnlyPaths=', text)
            self.assertNotIn('http-home', text)
        tunnel = (ROOT / 'deploy/systemd/relayforge-tunnel.service').read_text()
        for value in ['RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
                      'ReadWritePaths=%t/relayforge-tunnel %h/.local/state/relayforge',
                      'ConditionPathExists=%h/.config/relayforge/tunnel/runtime-key',
                      '--control-plane.poll-timeout 6s', '--control-plane.initial-poll-timeout 6s',
                      '--control-plane.poll-deadline-guardrail 5s']:
            self.assertIn(value, tunnel)

if __name__ == '__main__':
    unittest.main()
