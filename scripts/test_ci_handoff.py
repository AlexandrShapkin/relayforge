import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'ci' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


review = load('review_handoff')
release = load('release_arch')


class HandoffTests(unittest.TestCase):
    def test_missing_late_revoked_deleted_and_changed_identity(self):
        head, base = 'a' * 40, 'b' * 40
        comments = []
        self.assertFalse(review.accepted(comments, head, base))
        body = f'Independent technical ACCEPT: {head}\nIndependent technical ACCEPT base: {base}'
        comments.append({'user': {'login': 'outsider'}, 'body': body})
        self.assertFalse(review.accepted(comments, head, base))
        comments.append({'user': {'login': 'AlexandrShapkin'}, 'body': body})
        self.assertTrue(review.accepted(comments, head, base))
        self.assertFalse(review.accepted(comments, 'c' * 40, base))
        self.assertFalse(review.accepted(comments, head, 'd' * 40))
        comments.append({'user': {'login': 'AlexandrShapkin'},
                         'body': f'Independent technical REJECT: {head}'})
        self.assertFalse(review.accepted(comments, head, base))
        comments.pop()
        comments.pop()
        self.assertFalse(review.accepted(comments, head, base))

    def test_only_latest_completed_workflow_scans_backlog(self):
        sha = 'a' * 40
        runs = {}
        for i, workflow in enumerate(release.REQUIRED, 1):
            runs[workflow] = dict(id=i, run_attempt=1, run_number=1, head_sha=sha,
                head_branch='main', event='push', repository={'full_name': release.REPO},
                path=f'.github/workflows/{workflow}', status='completed', conclusion='success',
                updated_at=f'2026-10-29T00:00:0{i}Z')
        def get(path):
            return {'workflow_runs': [runs[path.split('/')[2]]]}
        first, last = runs.values()
        self.assertFalse(release.elected_trigger(sha, first, get))
        self.assertTrue(release.elected_trigger(sha, last, get))
        last['status'] = 'in_progress'
        self.assertFalse(release.elected_trigger(sha, first, get))
        last['status'] = 'completed'
        first.update(run_attempt=2, updated_at='2026-10-29T00:01:00Z')
        self.assertTrue(release.elected_trigger(sha, first, get))
        self.assertFalse(release.elected_trigger(sha, dict(first, run_attempt=1), get))


class CoverageTests(unittest.TestCase):
    def test_push_and_pr_coverage_decisions(self):
        import os
        import subprocess
        import tempfile
        workflow = (ROOT / '.github/workflows/tests.yml').read_text()
        script = workflow.split('        run: |\n', 1)[1].split('\n  test:', 1)[0]
        script = '\n'.join(line[10:] for line in script.splitlines())
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            gh = directory / 'gh'
            gh.write_text('#!/bin/sh\nif [ "$API_FAIL" = 1 ]; then exit 1; fi\nprintf "%s" "$MATCHES"\n')
            gh.chmod(0o700)
            for event, ref, matches, expected in [
                ('push', 'refs/heads/topic', '1', 'false'),
                ('push', 'refs/heads/topic', '', 'true'),
                ('push', 'refs/heads/main', '1', 'true'),
                ('push', 'refs/tags/v1', '1', 'true'),
                ('pull_request', 'refs/pull/1/merge', '1', 'true'),
            ]:
                output = directory / 'output'
                output.write_text('')
                env = dict(os.environ, PATH=f'{tmp}:/usr/bin:/bin', EVENT=event,
                           REF=ref, SHA='a' * 40, MATCHES=matches, API_FAIL='0',
                           GITHUB_REPOSITORY=release.REPO, GITHUB_OUTPUT=str(output))
                result = subprocess.run(['bash', '-e', '-c', script], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text().strip(), f'run={expected}')
            env.update(EVENT='push', REF='refs/heads/topic', API_FAIL='1')
            self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env).returncode, 0)
