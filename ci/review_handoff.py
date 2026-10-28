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


def main():
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    if os.environ['GITHUB_REPOSITORY'] != REPO:
        raise SystemExit('wrong repository')
    number = (event.get('pull_request') or event.get('issue') or {}).get('number')
    # Main changes invalidate acceptance of the old base for every open PR.
    prs = ([api(f'pulls/{number}')] if number else
           api('pulls?state=open&base=main&per_page=100'))
    if not number and len(prs) >= 100:
        raise SystemExit('open PR pagination requires reconciliation')
    for pr in prs:
        if pr['state'] != 'open' or pr['base']['ref'] != 'main':
            continue
        head, base = pr['head']['sha'], pr['base']['sha']
        comments = api(f"issues/{pr['number']}/comments?per_page=100")
        ok = accepted(comments, head, base)
        latest = api(f"pulls/{pr['number']}")
        if (latest['head']['sha'], latest['base']['sha']) != (head, base):
            raise SystemExit('PR identity changed during review check; retry required')
        api(f'statuses/{head}', '-f', f'context={CONTEXT}', '-f',
            f"state={'success' if ok else 'failure'}", '-f',
            'description=' + ('Owner handoff matches independent review HEAD and base' if ok else
                             'Missing, revoked, stale HEAD/base independent review handoff'))


if __name__ == '__main__':
    main()
