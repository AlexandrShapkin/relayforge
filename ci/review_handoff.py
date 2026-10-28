#!/usr/bin/env python3
"""Trusted pre-merge owner handoff check; never execute PR code or certify review."""
import json
import os
import re
import subprocess
from pathlib import Path

REPO = 'AlexandrShapkin/relayforge'
CONTEXT = 'Independent technical ACCEPT'


def api(path, *args):
    return json.loads(subprocess.check_output(
        ['gh', 'api', f'repos/{REPO}/{path}', *args], text=True))


def accepted(comments, head, base=None):
    if len(comments) >= 100 or not re.fullmatch('[0-9a-f]{40}', head):
        return False
    accept = f'Independent technical ACCEPT: {head}'
    reject = f'Independent technical REJECT: {head}'
    handoffs = [c for c in comments if c['user']['login'] == REPO.split('/')[0]
                and (accept in c['body'].splitlines() or reject in c['body'].splitlines())]
    if not handoffs:
        return False
    lines = handoffs[-1]['body'].splitlines()
    return (accept in lines and reject not in lines
            and (base is None or f'Independent technical ACCEPT base: {base}' in lines))


def status(sha, state, description, get=api):
    if not re.fullmatch('[0-9a-f]{40}', sha or ''):
        raise ValueError('merge identity unavailable; no acceptance can be issued')
    get(f'statuses/{sha}', '-f', f'context={CONTEXT}', '-f', f'state={state}',
        '-f', f'description={description}')


def evaluate(pr, get=api):
    # The synthetic merge SHA binds both head AND base. Never issue a success on
    # the head SHA, where it could survive a base change. A missing/changed merge
    # identity has no successful status and blocks the required merge check.
    merge = pr.get('merge_commit_sha')
    status(merge, 'pending', 'Rechecking independent review handoff', get)
    try:
        head, base = pr['head']['sha'], pr['base']['sha']
        path = f"issues/{pr['number']}/comments?per_page=100"
        comments = get(path)
        latest = get(f"pulls/{pr['number']}")
        current = get(path)
        final = get(f"pulls/{pr['number']}")
        identity = lambda p: (p['head']['sha'], p['base']['sha'], p.get('merge_commit_sha'))
        if identity(pr) != identity(latest) or identity(pr) != identity(final):
            raise ValueError('PR head/base/merge identity changed; retry required')
        ok = comments == current and accepted(current, head, base)
        status(merge, 'success' if ok else 'failure',
               'Independent review matches HEAD and base' if ok else
               'Missing, changed, revoked or stale independent review handoff', get)
        return ok
    except Exception:
        status(merge, 'failure', 'Review re-evaluation failed; retry required', get)
        raise


def main():
    json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if os.environ['GITHUB_REPOSITORY'] != REPO:
        raise SystemExit('wrong repository')
    # GitHub concurrency keeps only one pending run. Sweep all open PRs on
    # every event so coalescing comments for different PRs cannot lose a
    # revocation. No event-supplied head or comment body is trusted.
    prs = api('pulls?state=open&base=main&per_page=100')
    failures = []
    for pr in prs:
        if pr['state'] != 'open' or pr['base']['ref'] != 'main':
            continue
        try:
            evaluate(pr)
        except Exception as error:
            failures.append(f"PR {pr['number']}: {type(error).__name__}")
    if len(prs) >= 100:
        failures.append('open PR pagination requires reconciliation')
    if failures:
        raise SystemExit('; '.join(failures))


if __name__ == '__main__':
    main()
