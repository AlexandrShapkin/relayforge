#!/usr/bin/python3
"""Trusted-main release gate and immutable publication; never execute PR artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

REPO = 'AlexandrShapkin/relayforge'
REQUIRED = {'tests.yml': {'test'},
            'rdc-independent.yml': {'verify-offline', 'arch-source', 'sandbox-integration'}}
ASSETS = {'SHA256SUMS', 'source.json', 'arch-packages.txt', 'rustc.txt', 'lifecycle.json', 'release.json'}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def api(path, *args):
    return json.loads(command('gh', 'api', f'repos/{REPO}/{path}', *args))


def accepted_runs(sha, get=api):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('full source SHA required')
    selected = {}
    for workflow, jobs in REQUIRED.items():
        runs = get(f'actions/workflows/{workflow}/runs?head_sha={sha}&event=push&per_page=100')['workflow_runs']
        candidates = [r for r in runs if r['head_sha'] == sha and r['head_branch'] == 'main'
                      and r['event'] == 'push' and r['repository']['full_name'] == REPO
                      and r['path'] == f'.github/workflows/{workflow}']
        if not candidates:
            return None
        latest = max(candidates, key=lambda r: (r['run_number'], r['run_attempt']))
        if latest['status'] != 'completed' or latest['conclusion'] != 'success':
            return None
        result = get(f"actions/runs/{latest['id']}/jobs?filter=latest&per_page=100")
        actual = result['jobs']
        if result['total_count'] != len(actual):
            raise ValueError('incomplete jobs response')
        # Every required native/functional/security job must pass.
        for name in jobs:
            matches = [j for j in actual if j['name'] == name]
            if len(matches) != 1 or matches[0]['conclusion'] != 'success':
                return None
        if any(j['conclusion'] != 'success' for j in actual):
            return None
        selected[workflow] = latest['id']
    return selected


def accepted_merge(sha, get=api):
    """Require the independent exact-PR-head handoff, not an author's green CI."""
    prs = get(f'commits/{sha}/pulls')
    for pr in prs:
        if (not pr['merged_at'] or pr['base']['ref'] != 'main'
                or pr['base']['repo']['full_name'] != REPO or pr['merge_commit_sha'] != sha):
            continue
        head = pr['head']['sha']
        comments = get(f"issues/{pr['number']}/comments?per_page=100")
        # Fail closed on pagination rather than overlooking a later revocation.
        if len(comments) >= 100:
            raise ValueError('review handoff requires bounded explicit reconciliation')
        marker = f'Independent technical ACCEPT: {head}'
        refusal = f'Independent technical REJECT: {head}'
        handoffs = [c for c in comments if c['user']['login'] == REPO.split('/')[0]
                    and (marker in c['body'].splitlines() or refusal in c['body'].splitlines())]
        if handoffs and marker in handoffs[-1]['body'].splitlines():
            return True
    return False


def release_files(directory, sha, runs):
    identity = json.loads((directory / 'source.json').read_text())
    if identity['source_sha'] != sha or identity['activation_allowed'] is not False:
        raise ValueError('source identity mismatch')
    if not re.fullmatch(r'v\d+\.\d+\.\d+', identity['tag']):
        raise ValueError('invalid immutable tag')
    expected = f"relayforge-{identity['pkgver']}-1-x86_64.pkg.tar.zst"
    if not re.fullmatch(r'relayforge-\d+\.\d+\.\d+\.r\d+\.g[0-9a-f]{12}-1-x86_64.pkg.tar.zst', expected):
        raise ValueError('invalid package identity')
    # Input checksums come from the successful build, before any metadata generation.
    sums = {}
    for line in (directory / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split('  ')
        name = name.removeprefix('./')
        if not re.fullmatch('[0-9a-f]{64}', digest) or '/' in name or name in sums:
            raise ValueError('invalid build checksums')
        sums[name] = digest
    for name in (expected, 'source.json', 'arch-packages.txt', 'rustc.txt', 'lifecycle.json'):
        if hashlib.sha256((directory / name).read_bytes()).hexdigest() != sums.get(name):
            raise ValueError('tested artifact checksum mismatch')
    lifecycle = json.loads((directory / 'lifecycle.json').read_text())
    if lifecycle['source_sha'] != sha or lifecycle['package'] != expected or lifecycle['sha256'] != sums[expected] or lifecycle['lifecycle'] != 'PASS':
        raise ValueError('installed lifecycle evidence mismatch')
    record = {'schema_version': 1, 'source_sha': sha, 'build_sha': sha,
              'package': expected, 'package_sha256': sums[expected], 'required_runs': runs,
              'run_urls': [f'https://github.com/{REPO}/actions/runs/{r}' for r in runs.values()],
              'arch_image': 'archlinux/archlinux@sha256:676f4d5b2cacc259ab30b1e871a272bd4a2e023a901f725fb1b12c84dc355f10',
              'arch_snapshot': '2026/09/25', 'live_acceptance': False}
    (directory / 'release.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    names = (ASSETS - {'SHA256SUMS'}) | {expected}
    # Output only distributable files; operational source TARs stay CI evidence.
    checksums = ''.join(f'{hashlib.sha256((directory / n).read_bytes()).hexdigest()}  {n}\n' for n in sorted(names))
    (directory / 'SHA256SUMS').write_text(checksums)
    return identity, names | {'SHA256SUMS'}


def verify_existing(directory, names, release, sha, tag):
    if release['tag_name'] != tag or release['target_commitish'] != sha:
        raise ValueError('existing release source conflict')
    assets = release['assets']
    if len(assets) != len(names) or {a['name'] for a in assets} != names:
        raise ValueError('existing immutable asset inventory differs; no overwrite')
    with tempfile.TemporaryDirectory(prefix='relayforge-release-verify-') as tmp:
        subprocess.run(['gh', 'release', 'download', tag, '--repo', REPO, '--dir', tmp], check=True)
        for name in names:
            if (Path(tmp) / name).read_bytes() != (directory / name).read_bytes():
                raise ValueError('existing immutable asset bytes differ; no overwrite')


def publish(directory, sha, runs):
    # Re-query directly before write; gate is not a stale permission receipt.
    if accepted_runs(sha) != runs:
        raise ValueError('required exact-head checks changed')
    if not accepted_merge(sha):
        raise ValueError('merged main PR lacks independent exact-head ACCEPT handoff')
    identity, names = release_files(directory, sha, runs)
    tag = identity['tag']
    # A source SHA must be in protected-by-process main history, even if newer main exists.
    comparison = api(f'compare/{sha}...main')
    if comparison['status'] not in ('ahead', 'identical') or comparison['merge_base_commit']['sha'] != sha:
        raise ValueError('source no longer belongs to main history')
    # Do not depend on GitHub setting immutability to avoid our own overwrites.
    releases = json.loads(command('gh', 'api', '--paginate', '--slurp', f'repos/{REPO}/releases?per_page=100'))
    all_releases = [r for page in releases for r in page]
    existing = next((r for r in all_releases if r['tag_name'] == tag), None)
    if existing:
        verify_existing(directory, names, existing, sha, tag)
        if existing['draft']:
            raise ValueError('matching draft retained; owner must reconcile incomplete publication')
        print(f'exact immutable release already published: {tag}')
        return
    # Enforce monotonic Arch and SemVer order, not lexical short-SHA ordering.
    for release in all_releases:
        match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', release['tag_name'])
        if match and tuple(map(int, tag[1:].split('.'))) <= tuple(map(int, match.groups())):
            raise ValueError('release sequence must be strictly increasing')
    # Annotated tag; never move/reuse an existing ref. Partial failures retain evidence.
    tag_object = api('git/tags', '-X', 'POST', '-f', f'tag={tag}', '-f',
                     f'message=RelayForge {tag}; source {sha}; exact-head runs {json.dumps(runs, sort_keys=True)}',
                     '-f', f'object={sha}', '-f', 'type=commit')
    api('git/refs', '-X', 'POST', '-f', f'ref=refs/tags/{tag}', '-f', f"sha={tag_object['sha']}")
    notes = directory / 'notes.md'
    notes.write_text(f'''RelayForge {tag} — canonical Arch Linux x86_64 package.

This release replaces manual binary copying as the normal distribution channel.
Pacman owns the binaries and inactive HTTP user-unit template. Installation,
updates and removal never authorize service activation or erase user credentials.

Source/build: `{sha}`. Exact-head required CI: {record_urls(runs)}.
Verify SHA256SUMS and source.json before `pacman -U`. Read the included Arch
packaging guide for explicit local setup, migration, downgrade and removal.
Downgrade restores package-owned files only; it is not a live recovery receipt.
User-data purge requires a separate reviewed plan and terminal confirmation.

Compatibility: provisional 0.1 source protocol; no general shell, automatic
deployment or live readiness claim. Physical authenticated tunnel/recovery gates
remain host-only. Existing Issue #89 evidence is not retroactively accepted.
Ubuntu/Debian packages are future work. Arch snapshot/toolchain details and CI
provenance are attached. These are CI-tested bytes, not reproducible-build proof.
''')
    subprocess.run(['gh', 'release', 'create', tag, '--repo', REPO, '--target', sha,
                    '--verify-tag', '--draft', '--title', f'RelayForge {tag}', '--notes-file', str(notes),
                    *[str(directory / n) for n in sorted(names)]], check=True)
    release = api(f'releases/tags/{tag}')
    verify_existing(directory, names, release, sha, tag)
    subprocess.run(['gh', 'release', 'edit', tag, '--repo', REPO, '--draft=false'], check=True)


def record_urls(runs):
    return ', '.join(f'https://github.com/{REPO}/actions/runs/{r}' for r in runs.values())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['gate', 'publish'])
    parser.add_argument('--sha', required=True)
    parser.add_argument('--directory', type=Path, default=Path('dist'))
    args = parser.parse_args()
    if os.environ.get('GITHUB_REPOSITORY') != REPO or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_run':
        raise SystemExit('trusted workflow_run context required')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())['workflow_run']
    if (event['event'] != 'push' or event['head_branch'] != 'main' or event['head_sha'] != args.sha
            or event['repository']['full_name'] != REPO):
        raise SystemExit('only exact-source main push may release')
    runs = accepted_runs(args.sha)
    if args.command == 'gate':
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'ready={str(runs is not None).lower()}\n')
            if runs:
                output.write(f"run_id={runs['rdc-independent.yml']}\n")
    elif runs:
        publish(args.directory, args.sha, runs)
    else:
        raise SystemExit('all required same-SHA checks must pass')
