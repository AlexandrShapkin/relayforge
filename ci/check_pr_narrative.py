#!/usr/bin/env python3
"""Read PR metadata as data; reject a known post-merge publication blocker."""
import json
import os
from pathlib import Path

from release_arch import narrative_text


def check(event):
    pr = event['pull_request']
    if pr['base']['ref'] != 'main':
        return
    narrative_text(pr.get('body'))


if __name__ == '__main__':
    if os.environ['GITHUB_EVENT_NAME'] != 'pull_request':
        raise SystemExit('pull_request event required')
    check(json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()))
    print('PR release narrative structure verified; independent review still required')
