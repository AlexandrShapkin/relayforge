"""Small offline build-isolation regression usable by the first live task."""
from pathlib import Path
import unittest

from verify import commands


class DevelopmentAcceptanceTests(unittest.TestCase):
    def test_cargo_commands_use_explicit_isolated_target(self):
        root = Path('/tmp/acceptance-source')
        selected = [cmd for cmd in commands(root) if cmd[:1] == ['cargo'] and cmd[1] != 'fmt']
        self.assertEqual(len(selected), 3)
        for command in selected:
            self.assertEqual(command[command.index('--target-dir') + 1],
                             str(root / '.build/verification'))


if __name__ == '__main__':
    unittest.main()
