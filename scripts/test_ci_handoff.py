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


class ReevaluationTests(unittest.TestCase):
    def setUp(self):
        self.head, self.base, self.merge = 'a' * 40, 'b' * 40, 'c' * 40
        self.pr = dict(number=126, head={'sha': self.head}, base={'sha': self.base},
                       merge_commit_sha=self.merge)
        self.comments = [{'user': {'login': 'AlexandrShapkin'}, 'body':
            f'Independent technical ACCEPT: {self.head}\nIndependent technical ACCEPT base: {self.base}'}]
        self.writes = []

    def api(self, path, *args):
        if path.startswith('statuses/'):
            self.writes.append((path, args))
            return {}
        if path.startswith('issues/'):
            return self.comments.copy()
        return self.pr.copy()

    def test_success_only_on_merge_identity(self):
        self.assertTrue(review.evaluate(self.pr, self.api))
        self.assertTrue(all(path == f'statuses/{self.merge}' for path, _ in self.writes))
        self.assertIn('state=pending', self.writes[0][1])
        self.assertIn('state=success', self.writes[-1][1])

    def test_comment_revocation_between_reads_fails(self):
        count = 0
        def api(path, *args):
            nonlocal count
            if path.startswith('issues/'):
                count += 1
                if count == 2:
                    return []
            return self.api(path, *args)
        self.assertFalse(review.evaluate(self.pr, api))
        self.assertIn('state=failure', self.writes[-1][1])

    def test_api_exception_clears_previous_success(self):
        def api(path, *args):
            if path.startswith('issues/'):
                raise OSError('API unavailable')
            return self.api(path, *args)
        with self.assertRaises(OSError):
            review.evaluate(self.pr, api)
        self.assertIn('state=pending', self.writes[0][1])
        self.assertIn('state=failure', self.writes[-1][1])

    def test_base_change_invalidates_old_merge_status(self):
        def api(path, *args):
            if path.startswith('pulls/'):
                return dict(self.pr, base={'sha': 'd' * 40}, merge_commit_sha='e' * 40)
            return self.api(path, *args)
        with self.assertRaises(ValueError):
            review.evaluate(self.pr, api)
        self.assertIn('state=failure', self.writes[-1][1])

    def test_null_identity_then_valid_identity(self):
        pending = dict(self.pr, merge_commit_sha=None)
        def unavailable(path, *args):
            self.fail('unevaluable PR must not read review or write status')
        self.assertIsNone(review.evaluate(pending, unavailable))
        self.assertEqual(self.writes, [])
        self.assertTrue(review.evaluate(self.pr, self.api))
        self.assertIn('state=success', self.writes[-1][1])

    def test_scheduled_reconciliation_uses_real_retry_and_evaluation(self):
        import os
        import tempfile
        from unittest.mock import patch
        # All scenarios enter main(), with real evaluate() and no wall-clock wait.
        for scenario in ('recover', 'persistent', 'refresh_error', 'comments_error', 'stale'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                self.writes.clear()
                event = Path(tmp) / 'event.json'
                event.write_text('{"schedule":"7,22,37,52 * * * *"}')
                null = dict(self.pr, number=64, state='open',
                            base=dict(self.pr['base'], ref='main'), merge_commit_sha=None)
                valid = dict(null, number=1, merge_commit_sha=self.merge)
                reads = 0
                def api(path, *args):
                    nonlocal reads
                    if path.startswith('pulls?'):
                        return [null, valid]
                    if path == 'pulls/64':
                        reads += 1
                        if scenario == 'refresh_error':
                            raise OSError('refresh unavailable')
                        if scenario == 'persistent' or reads == 1:
                            return null.copy()
                        recovered = dict(null, merge_commit_sha='d' * 40)
                        if scenario == 'stale' and reads >= 3:
                            recovered['base'] = dict(recovered['base'], sha='e' * 40)
                        return recovered
                    if path == 'pulls/1':
                        return valid.copy()
                    if path.startswith('issues/64/') and scenario == 'comments_error':
                        raise OSError('comments unavailable')
                    return self.api(path, *args)
                evaluate = review.evaluate
                with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event),
                                GITHUB_REPOSITORY=review.REPO, GITHUB_EVENT_NAME='schedule'), \
                        patch.object(review, 'api', side_effect=api), \
                        patch.object(review, 'evaluate', side_effect=lambda pr: evaluate(pr, api)), \
                        patch.object(review.time, 'sleep') as pause:
                    if scenario in ('refresh_error', 'comments_error', 'stale'):
                        with self.assertRaisesRegex(SystemExit, 'PR 64:'):
                            review.main()
                    else:
                        review.main()
                    self.assertEqual([c.args[0] for c in pause.call_args_list],
                                     [2] if scenario == 'refresh_error' else [2, 5])
                successes = [path for path, args in self.writes if 'state=success' in args]
                self.assertIn(f'statuses/{self.merge}', successes)
                self.assertEqual(f'statuses/{"d" * 40}' in successes, scenario == 'recover')
                if scenario in ('persistent', 'refresh_error'):
                    self.assertEqual(reads, 1 if scenario == 'refresh_error' else 2)
                    self.assertTrue(all(path == f'statuses/{self.merge}' for path, _ in self.writes))
                if scenario in ('comments_error', 'stale'):
                    self.assertIn('state=failure', self.writes[-1][1])

    def test_later_scheduled_sweep_recovers_after_exhausted_budget(self):
        import os
        import tempfile
        from unittest.mock import patch
        pr = dict(self.pr, state='open', base=dict(self.pr['base'], ref='main'))
        current = dict(pr, merge_commit_sha=None)
        def api(path, *args):
            if path.startswith('pulls?'):
                return [current.copy()]
            if path.startswith('pulls/'):
                return current.copy()
            return self.api(path, *args)
        evaluate = review.evaluate
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / 'event.json'
            event.write_text('{}')
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_REPOSITORY=review.REPO), \
                    patch.object(review, 'api', side_effect=api), \
                    patch.object(review, 'evaluate', side_effect=lambda pr: evaluate(pr, api)), \
                    patch.object(review.time, 'sleep') as pause:
                review.main()
                self.assertEqual(pause.call_count, 2)
                self.assertEqual(self.writes, [])
                current = pr
                review.main()
                self.assertEqual(pause.call_count, 2)
                self.assertIn('state=success', self.writes[-1][1])

    def test_identity_changes_at_either_revalidation_fail_closed(self):
        for field in ('head', 'base', 'merge_commit_sha'):
            for read in (1, 2):
                with self.subTest(field=field, read=read):
                    self.writes.clear()
                    count = 0
                    def api(path, *args):
                        nonlocal count
                        if path.startswith('pulls/'):
                            count += 1
                            if count == read:
                                value = {'sha': 'd' * 40} if field != 'merge_commit_sha' else None
                                return dict(self.pr, **{field: value})
                        return self.api(path, *args)
                    with self.assertRaises(ValueError):
                        review.evaluate(self.pr, api)
                    self.assertIn('state=failure', self.writes[-1][1])
                    self.assertFalse(any('state=success' in args for _, args in self.writes))

    def test_missing_rejected_or_stale_review_fails(self):
        for comments in ([], self.comments + [{'user': {'login': 'AlexandrShapkin'},
                'body': f'Independent technical REJECT: {self.head}'}],
                [{'user': {'login': 'AlexandrShapkin'}, 'body':
                  f'Independent technical ACCEPT: {self.head}\nIndependent technical ACCEPT base: {"d" * 40}'}]):
            with self.subTest(comments=comments):
                self.comments = comments
                self.assertFalse(review.evaluate(self.pr, self.api))
                self.assertIn('state=failure', self.writes[-1][1])

    def test_transient_api_failure_then_retry(self):
        def api(path, *args):
            if path.startswith('pulls/'):
                raise OSError('transient API failure')
            return self.api(path, *args)
        with self.assertRaises(OSError):
            review.evaluate(self.pr, api)
        self.assertIn('state=failure', self.writes[-1][1])
        self.assertTrue(review.evaluate(self.pr, self.api))

    def test_status_write_failures_propagate(self):
        for state in ('pending', 'success', 'failure'):
            with self.subTest(state=state):
                self.writes.clear()
                def api(path, *args):
                    if f'state={state}' in args:
                        raise OSError('status write failed')
                    if state == 'failure' and path.startswith('issues/'):
                        return []
                    return self.api(path, *args)
                with self.assertRaises(OSError):
                    review.evaluate(self.pr, api)
                self.assertFalse(any('state=success' in args for _, args in self.writes))

    def test_mixed_population_sweep(self):
        import os
        import tempfile
        from unittest.mock import patch
        for broken in (False, True):
            with self.subTest(api_failure=broken), tempfile.TemporaryDirectory() as tmp:
                self.writes.clear()
                event = Path(tmp) / 'event.json'
                event.write_text('{}')
                prs = [dict(self.pr, number=n, state='open', base=dict(self.pr['base'], ref='main'),
                            merge_commit_sha=None if n in (64, 66, 76) else str(n) * 40)
                       for n in (64, 1, 66, 2, 76, 3)]
                def api(path, *args):
                    if path.startswith('pulls?'):
                        return prs
                    if path.startswith('pulls/'):
                        return next(pr for pr in prs if pr['number'] == int(path.split('/')[1]))
                    if path.startswith('issues/2/'):
                        if broken:
                            raise OSError('transient API failure')
                        return []
                    return self.api(path, *args)
                evaluate = review.evaluate
                with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_REPOSITORY=review.REPO), \
                        patch.object(review, 'api', side_effect=api), \
                        patch.object(review.time, 'sleep'), \
                        patch.object(review, 'evaluate', side_effect=lambda pr: evaluate(pr, api)):
                    if broken:
                        with self.assertRaisesRegex(SystemExit, 'PR 2: OSError'):
                            review.main()
                    else:
                        review.main()
                self.assertEqual([(path, next(a for a in args if a.startswith('state=')))
                                  for path, args in self.writes],
                    [(f'statuses/{str(n) * 40}', f'state={state}')
                     for n in (1, 2, 3) for state in ('pending', 'failure' if n == 2 else 'success')])

    def test_new_release_policy_requires_first_parent_base(self):
        from unittest.mock import patch
        pr = dict(self.pr, merged_at='now', merge_commit_sha=self.merge,
                  base={'ref': 'main', 'repo': {'full_name': release.REPO}})
        def api(path):
            return [pr] if path.startswith('commits/') else self.comments
        with patch.object(release, 'command', side_effect=[self.base, 'tracked']):
            self.assertTrue(release.accepted_merge(self.merge, api))
        self.comments[0]['body'] = f'Independent technical ACCEPT: {self.head}'
        with patch.object(release, 'command', side_effect=[self.base, 'tracked']):
            self.assertFalse(release.accepted_merge(self.merge, api))
        with patch.object(release, 'command', side_effect=[self.base, '']):
            self.assertTrue(release.accepted_merge(self.merge, api))

    def test_bounded_comments_fail_closed(self):
        self.assertFalse(review.accepted(self.comments * 100, self.head, self.base))


class AggregateTests(unittest.TestCase):
    def test_failed_or_skipped_pr_jobs_never_satisfy_required_aggregate(self):
        import json
        import os
        import subprocess
        for filename, job in [('tests.yml', 'test'), ('rdc-independent.yml', 'verify-offline')]:
            text = (ROOT / '.github/workflows' / filename).read_text()
            script = text.split('      - name: Fail closed on missing or failed verification\n        run: |\n')[1]
            script = '\n'.join(line[10:] for line in script.splitlines())
            for event, ref, discovery, outcome, should_pass in [
                ('pull_request', 'refs/pull/1/merge', 'true', 'success', True),
                ('pull_request', 'refs/pull/1/merge', 'true', 'skipped', False),
                ('pull_request', 'refs/pull/1/merge', 'false', 'skipped', False),
                ('push', 'refs/heads/main', 'false', 'skipped', False),
                ('push', 'refs/heads/topic', 'false', 'skipped', True),
                ('push', 'refs/heads/main', 'true', 'failure', False),
            ]:
                results = {'coverage': {'result': 'success', 'outputs': {'run': discovery}},
                           job: {'result': outcome}}
                env = dict(os.environ, RESULTS=json.dumps(results), EVENT=event, REF=ref)
                r = subprocess.run(['bash', '-e', '-c', script], env=env, capture_output=True)
                self.assertEqual(r.returncode == 0, should_pass, (filename, event, outcome))
                results['coverage']['result'] = 'failure'
                env['RESULTS'] = json.dumps(results)
                self.assertNotEqual(subprocess.run(['bash', '-e', '-c', script], env=env,
                    capture_output=True).returncode, 0)


class CoverageFilterTests(unittest.TestCase):
    def test_real_query_filters_base_fork_head_and_branch(self):
        import json
        import os
        import subprocess
        import tempfile
        for name, end in [('tests.yml', '\n  test:'), ('rdc-independent.yml', '\n  verify-offline:')]:
            text = (ROOT / '.github/workflows' / name).read_text()
            script = text.split('        run: |\n', 1)[1].split(end, 1)[0]
            script = '\n'.join(line[10:] for line in script.splitlines())
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                gh = directory / 'gh'
                gh.write_text('#!/bin/bash\nwhile [[ "$1" != --jq ]]; do shift; done\nshift\nprintf "%s" "$FIXTURE" | /usr/bin/jq -r "$1"\n')
                gh.chmod(0o700)
                valid = {'number': 126, 'base': {'ref': 'main'}, 'head': {
                    'repo': {'full_name': release.REPO}, 'ref': 'topic', 'sha': 'a' * 40}}
                for field, value in [('base', 'other'), ('repo', 'fork/repo'),
                                     ('ref', 'stacked'), ('sha', 'b' * 40), ('valid', '')]:
                    pr = json.loads(json.dumps(valid))
                    if field == 'base': pr['base']['ref'] = value
                    elif field == 'repo': pr['head']['repo']['full_name'] = value
                    elif field != 'valid': pr['head'][field] = value
                    output = directory / 'output'
                    output.write_text('')
                    env = dict(os.environ, PATH=f'{tmp}:/usr/bin:/bin', EVENT='push',
                        REF='refs/heads/topic', SHA='a' * 40, FIXTURE=json.dumps([pr]),
                        GITHUB_REPOSITORY=release.REPO, GITHUB_OUTPUT=str(output))
                    result = subprocess.run(['bash', '-e', '-c', script], env=env, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text().strip(),
                                     'run=false' if field == 'valid' else 'run=true')

    def test_main_sweep_continues_after_one_pr_failure(self):
        import json
        import os
        import tempfile
        from unittest.mock import patch
        prs = [dict(number=i, state='open', base={'ref': 'main'}) for i in [1, 2]]
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / 'event.json'
            event.write_text(json.dumps({'ref': 'refs/heads/main'}))
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_REPOSITORY=release.REPO), \
                    patch.object(review, 'api', return_value=prs), \
                    patch.object(review, 'evaluate', side_effect=[OSError('API failure'), True]) as evaluate:
                with self.assertRaises(SystemExit): review.main()
                self.assertEqual(evaluate.call_count, 2)


class ElectionPlanTests(unittest.TestCase):
    def test_non_elected_event_never_scans_history(self):
        from unittest.mock import patch
        with patch.object(release, 'elected_trigger', return_value=False), \
                patch.object(release, 'main_history') as history:
            self.assertEqual(release.release_plan('a' * 40, {}), [])
            history.assert_not_called()

    def test_elected_event_preserves_backlog_plan(self):
        from unittest.mock import patch
        commits = ['a' * 40, 'b' * 40]
        plan = [{'sha': sha, 'run_id': i} for i, sha in enumerate(commits)]
        with patch.object(release, 'elected_trigger', return_value=True), \
                patch.object(release, 'main_history', return_value=commits), \
                patch.object(release, 'all_releases', return_value=[]), \
                patch.object(release, 'pending_main', return_value=plan) as pending:
            self.assertEqual(release.release_plan(commits[-1], {}), plan)
            pending.assert_called_once_with(commits[-1], commits, [])


class CoalescingTests(unittest.TestCase):
    def test_comment_event_sweeps_other_prs_too(self):
        import json
        import os
        import tempfile
        from unittest.mock import patch
        prs = [dict(number=i, state='open', base={'ref': 'main'}) for i in [1, 2]]
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp) / 'event.json'
            event.write_text(json.dumps({'issue': {'number': 2}, 'action': 'deleted'}))
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event), GITHUB_REPOSITORY=release.REPO), \
                    patch.object(review, 'api', return_value=prs) as api, \
                    patch.object(review, 'evaluate', return_value=True) as evaluate:
                review.main()
                api.assert_called_once_with('pulls?state=open&base=main&per_page=100')
                self.assertEqual([call.args[0]['number'] for call in evaluate.call_args_list], [1, 2])


class ReconciliationWorkflowTests(unittest.TestCase):
    def test_schedule_trust_concurrency_and_lightweight_job(self):
        text = (ROOT / '.github/workflows/review-handoff.yml').read_text()
        self.assertIn("cron: '7,22,37,52 * * * *'", text)
        self.assertIn("github.event_name == 'schedule' && 'refs/heads/main'", text)
        self.assertIn('github.event.pull_request.base.sha || github.sha', text)
        self.assertIn('group: review-handoff-repository', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertIn('timeout-minutes: 5', text)
        self.assertEqual(text.count('      - uses:'), 1)
        self.assertEqual(text.count('        run:'), 1)
        self.assertIn('run: python3 -B ci/review_handoff.py', text)
        self.assertNotIn('pull_request.head', text)
        for name in ('tests.yml', 'rdc-independent.yml', 'release-arch.yml'):
            self.assertNotIn('  schedule:', (ROOT / '.github/workflows' / name).read_text())
