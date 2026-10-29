"""Pre-merge metadata gate and publisher must agree without executing PR text."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'ci/check_pr_narrative.py'
HEADING = '## Problem and resulting behavior\n'


class NarrativePreflightTests(unittest.TestCase):
    def run_event(self, body, base='main', event_name='pull_request'):
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / 'event.json'
            event.write_text(json.dumps({'pull_request': {'base': {'ref': base}, 'body': body}}))
            return subprocess.run([sys.executable, '-B', str(SCRIPT)],
                env={**os.environ, 'GITHUB_EVENT_NAME': event_name,
                     'GITHUB_EVENT_PATH': str(event)}, capture_output=True, text=True)

    def test_rejects_actual_missing_section_and_empty_or_excessive_narrative(self):
        # PR #76 passed native CI but failed publication with this heading.
        for body in [None, '## P2 review corrections — current handoff\n' + 'x' * 100,
                     HEADING + 'x' * 79, HEADING + 'x' * 12001,
                     HEADING + '\n## Verification\n' + 'x' * 100]:
            with self.subTest(body_length=len(body or '')):
                result = self.run_event(body)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('narrative', result.stderr)

    def test_accepts_publisher_bounds_and_treats_text_as_data(self):
        for size in [80, 12000]:
            result = self.run_event(HEADING + 'x' * size + '\n## Verification\nchecks')
            self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / 'must-not-exist'
            body = HEADING + f'$(touch {sentinel}) `touch {sentinel}`\n' + 'x' * 80
            result = self.run_event(body)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(sentinel.exists())
            self.assertNotIn(str(sentinel), result.stdout + result.stderr)

    def test_other_base_is_outside_main_release_contract(self):
        self.assertEqual(self.run_event(None, base='historical-rehearsal').returncode, 0)

    def test_non_pr_event_cannot_use_preflight(self):
        self.assertNotEqual(self.run_event(HEADING + 'x' * 80, event_name='push').returncode, 0)


if __name__ == '__main__':
    unittest.main()
