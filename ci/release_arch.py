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
import tomllib

REPO = 'AlexandrShapkin/relayforge'
REQUIRED = {'tests.yml': {'test'},
            'rdc-independent.yml': {'verify-offline', 'arch-source', 'sandbox-integration'}}
ASSETS = {'SHA256SUMS', 'source.json', 'arch-packages.txt', 'rustc.txt', 'lifecycle.json', 'release.json'}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def api(path, *args):
    return json.loads(command('gh', 'api', f'repos/{REPO}/{path}', *args))


def inspect_runs(sha, get=api):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('full source SHA required')
    selected = {}
    for workflow, jobs in REQUIRED.items():
        jobs = jobs | ({'ubuntu-release'} if workflow == 'rdc-independent.yml' and ubuntu_assets(sha) else set())
        runs = get(f'actions/workflows/{workflow}/runs?head_sha={sha}&event=push&per_page=100')['workflow_runs']
        candidates = [r for r in runs if r['head_sha'] == sha and r['head_branch'] == 'main'
                      and r['event'] == 'push' and r['repository']['full_name'] == REPO
                      and r['path'] == f'.github/workflows/{workflow}']
        if not candidates:
            return 'pending', None
        latest = max(candidates, key=lambda r: (r['run_number'], r['run_attempt']))
        if latest['status'] != 'completed':
            return 'pending', None
        if latest['conclusion'] != 'success':
            return 'failed', None
        result = get(f"actions/runs/{latest['id']}/jobs?filter=latest&per_page=100")
        actual = result['jobs']
        if result['total_count'] != len(actual):
            raise ValueError('incomplete jobs response')
        # Every required native/functional/security job must pass.
        for name in jobs:
            matches = [j for j in actual if j['name'] == name]
            if len(matches) != 1 or matches[0]['conclusion'] != 'success':
                return 'failed', None
        if any(j['conclusion'] != 'success' for j in actual):
            return 'failed', None
        selected[workflow] = latest['id']
    return 'success', selected


def accepted_runs(sha, get=api):
    state, runs = inspect_runs(sha, get)
    return runs if state == 'success' else None



def accepted_merge(sha, get=api):
    """Require the independent exact-PR-head handoff, not an author's green CI."""
    prs = get(f'commits/{sha}/pulls')
    for pr in prs:
        if (not pr['merged_at'] or pr['base']['ref'] != 'main'
                or pr['base']['repo']['full_name'] != REPO or pr['merge_commit_sha'] != sha):
            continue
        head = pr['head']['sha']
        # Activate the base-bound policy only after it exists in the merge's
        # first parent. Historical immutable releases keep their original gate.
        parent = command('git', 'rev-parse', f'{sha}^1')
        base_bound = bool(command('git', 'ls-tree', parent, '--', 'ci/review_handoff.py'))
        comments = get(f"issues/{pr['number']}/comments?per_page=100")
        # Fail closed on pagination rather than overlooking a later revocation.
        if len(comments) >= 100:
            raise ValueError('review handoff requires bounded explicit reconciliation')
        marker = f'Independent technical ACCEPT: {head}'
        refusal = f'Independent technical REJECT: {head}'
        handoffs = [c for c in comments if c['user']['login'] == REPO.split('/')[0]
                    and (marker in c['body'].splitlines() or refusal in c['body'].splitlines())]
        if (handoffs and marker in handoffs[-1]['body'].splitlines()
                and refusal not in handoffs[-1]['body'].splitlines()
                and (not base_bound or f'Independent technical ACCEPT base: {parent}'
                     in handoffs[-1]['body'].splitlines())):
            return True
    return False


def elected_trigger(sha, event, get=api):
    """Only the last completed required workflow scans history; keep both triggers.

    A retry of either required workflow can recover a failed/pending counterpart.
    The expensive gate still rechecks every required job and historical artifact.
    """
    completed = []
    for workflow in REQUIRED:
        runs = get(f'actions/workflows/{workflow}/runs?head_sha={sha}&event=push&per_page=100')['workflow_runs']
        candidates = [r for r in runs if r['head_sha'] == sha and r['head_branch'] == 'main'
                      and r['event'] == 'push' and r['repository']['full_name'] == REPO
                      and r['path'] == f'.github/workflows/{workflow}']
        if not candidates:
            return False
        latest = max(candidates, key=lambda r: (r['run_number'], r['run_attempt']))
        if latest['status'] != 'completed' or latest['conclusion'] != 'success':
            return False
        completed.append(latest)
    winner = max(completed, key=lambda r: (r['updated_at'], r['id']))
    return (event['id'], event['run_attempt']) == (winner['id'], winner['run_attempt'])


def release_plan(sha, event):
    if not elected_trigger(sha, event):
        return []
    return pending_main(sha, main_history(), all_releases())


def main_history():
    """Only first-parent main commits since this delivery policy was introduced."""
    additions = command('git', 'log', '--first-parent', '--diff-filter=A', '--format=%H',
                        '--', '.github/workflows/release-arch.yml').splitlines()
    if not additions:
        raise ValueError('release policy introduction unavailable')
    first = additions[-1]
    commits = command('git', 'rev-list', '--first-parent', '--reverse', f'{first}^..HEAD').splitlines()
    if len(commits) > 1000:
        raise ValueError('release history requires owner archival review')
    return commits


def pending_main(trigger_sha, commits, releases, get=api):
    """Drain missed completion events in source order; CI failure never publishes."""
    plan = []
    for sha in commits:
        tag, package = source_names(sha)
        matches = [r for r in releases if r['tag_name'] == tag or r['target_commitish'] == sha]
        if matches:
            if len(matches) != 1:
                raise ValueError('conflicting release history')
            if (matches[0]['tag_name'] != tag or
                    matches[0]['target_commitish'] != sha):
                raise ValueError('existing release source conflict')
            if not matches[0]['draft']:
                verify_published(matches[0], sha, tag, package, get)
                continue
            # A partial draft is not a published historical release. Recover
            # only through fresh exact-head CI and independent review.
        state, runs = inspect_runs(sha, get)
        if state == 'pending':
            break  # preserve monotonic ordering until the predecessor completes
        if state == 'failed':
            continue  # failed exact-main source is never a distributable release
        if not accepted_merge(sha, get):
            raise ValueError(f'independent review handoff missing for main {sha}')
        plan.append({'sha': sha, 'run_id': runs['rdc-independent.yml']})
    if len(plan) > 100:
        raise ValueError('too many pending releases; owner reconciliation required')
    return plan


def source_names(sha):
    """Derive immutable names from committed source, independently of Release data."""
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('full source SHA required')
    version = tomllib.loads(command('git', 'show', f'{sha}:Cargo.toml'))['workspace']['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('invalid source version')
    revision = int(command('git', 'rev-list', '--first-parent', '--count', sha))
    major, minor, _ = version.split('.')
    return (f'v{major}.{minor}.{revision}',
            f'relayforge-{version}.r{revision}.g{sha[:12]}-1-x86_64.pkg.tar.zst')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_ubuntu(directory, sha, package):
    """Verify exact tested bytes and the independent installed-package receipt."""
    source = json.loads((directory / 'ubuntu-source.json').read_text())
    receipt = json.loads((directory / 'ubuntu-verification.json').read_text())
    if (source['source_sha'] != sha or source['activation_allowed'] is not False
            or source['distribution'] != 'ubuntu-24.04'
            or source['package_architecture'] != 'amd64'
            or package != f"relayforge_{source['pkgver']}_amd64.deb"
            or set(source['binaries_sha256']) != {'relayforge-agent', 'relayforge-mcp'}
            or any(not re.fullmatch('[0-9a-f]{64}', v)
                   for v in source['binaries_sha256'].values())):
        raise ValueError('Ubuntu source identity mismatch')
    expected = {'schema_version': 1, 'source_sha': sha, 'package': package,
                'sha256': digest(directory / package), 'distribution': 'ubuntu-24.04',
                'architecture': 'amd64', 'installed_checks': 'PASS', 'activation_allowed': False}
    if receipt != expected:
        raise ValueError('Ubuntu independent verification mismatch')
    sums = {}
    for line in (directory / 'ubuntu-SHA256SUMS').read_text().splitlines():
        checksum, name = line.split('  ')
        if name in sums or name not in {package, 'source.json'}:
            raise ValueError('invalid Ubuntu input inventory')
        sums[name] = checksum
    if sums != {package: expected['sha256'], 'source.json': digest(directory / 'ubuntu-source.json')}:
        raise ValueError('Ubuntu tested checksum mismatch')
    return {package, 'ubuntu-source.json', 'ubuntu-verification.json', 'ubuntu-SHA256SUMS'}


def ubuntu_assets(sha):
    # Historical releases keep their original matrix; never infer it from assets.
    if not command('git', 'ls-tree', sha, '--', 'ci/ubuntu_release.py'):
        return set()
    _, arch = source_names(sha)
    version = arch.removeprefix('relayforge-').removesuffix('-1-x86_64.pkg.tar.zst')
    return {f'relayforge_{version}_amd64.deb', 'ubuntu-source.json',
            'ubuntu-verification.json', 'ubuntu-SHA256SUMS'}


def verify_ubuntu_release(directory, sha):
    names = ubuntu_assets(sha)
    if names:
        package, = (n for n in names if n.endswith('.deb'))
        if verify_ubuntu(directory, sha, package) != names:
            raise ValueError('Ubuntu release inventory mismatch')
    return names


def tunnel_assets(sha):
    """Read historical package contract from committed source, not Release claims."""
    path = 'packaging/arch/tunnel-client/upstream.json'
    if not command('git', 'ls-tree', sha, '--', path):
        return set()
    lock = json.loads(command('git', 'show', f'{sha}:{path}'))
    version, revision = lock['version'], lock['pkgrel']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or type(revision) is not int or revision < 1:
        raise ValueError('invalid independent tunnel package identity')
    return {f'tunnel-client-{version}-{revision}-x86_64.pkg.tar.zst'}


def verify_tunnel(directory, sha, identity, lifecycle, sums):
    extra = tunnel_assets(sha)
    if extra:
        name, = extra
        if (identity.get('tunnel_package') != name or lifecycle.get('tunnel_package') != name
                or lifecycle.get('tunnel_lifecycle') != 'PASS'
                or lifecycle.get('tunnel_sha256') != sums.get(name)
                or hashlib.sha256((directory / name).read_bytes()).hexdigest() != sums.get(name)):
            raise ValueError('tested tunnel package/lifecycle mismatch')
    elif identity.get('tunnel_package') or lifecycle.get('tunnel_package'):
        raise ValueError('unexpected tunnel package contract')
    return extra


def verify_provenance(directory):
    # Authenticate the entire digest inventory, including release/source/lifecycle
    # records. A package-only attestation cannot authenticate those records.
    # workflow_run runs on current main, possibly newer than the package source;
    # the signed manifest binds that source, the certificate binds the publisher.
    subprocess.run(['gh', 'attestation', 'verify', str(directory / 'SHA256SUMS'),
                    '--repo', REPO, '--signer-workflow', f'{REPO}/.github/workflows/release-arch.yml',
                    '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners'], check=True)


def verify_published(release, sha, tag, package, get=api):
    """Durable authenticated evidence; never consult ephemeral Actions artifacts."""
    names = ASSETS | {package} | tunnel_assets(sha) | ubuntu_assets(sha)
    if release['tag_name'] != tag or release['target_commitish'] != sha:
        raise ValueError('existing release source conflict')
    assets = release['assets']
    if len(assets) != len(names) or {a['name'] for a in assets} != names:
        raise ValueError('existing immutable asset inventory differs; no overwrite')
    if tag_commit(tag, get) != sha:
        raise ValueError('existing immutable tag commit conflict')
    with tempfile.TemporaryDirectory(prefix='relayforge-history-') as tmp:
        directory = Path(tmp)
        subprocess.run(['gh', 'release', 'download', tag, '--repo', REPO, '--dir', tmp], check=True)
        verify_provenance(directory)
        sums = {}
        for line in (directory / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            if name not in names - {'SHA256SUMS'} or name in sums or not re.fullmatch('[0-9a-f]{64}', digest):
                raise ValueError('invalid authenticated release inventory')
            sums[name] = digest
        if set(sums) != names - {'SHA256SUMS'}:
            raise ValueError('incomplete authenticated release inventory')
        for name, digest in sums.items():
            if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
                raise ValueError('authenticated release checksum mismatch')
        record = json.loads((directory / 'release.json').read_text())
        runs = record['required_runs']
        if (record['schema_version'] != 1 or record['live_acceptance'] is not False
                or set(runs) != set(REQUIRED) or any(type(r) is not int or r <= 0 for r in runs.values())
                or record['source_sha'] != sha or record['build_sha'] != sha
                or record['package'] != package or record['package_sha256'] != sums[package]):
            raise ValueError('authenticated release identity mismatch')
        identity = json.loads((directory / 'source.json').read_text())
        lifecycle = json.loads((directory / 'lifecycle.json').read_text())
        verify_tunnel(directory, sha, identity, lifecycle, sums)
        verify_ubuntu_release(directory, sha)
        # Validate historical records without regenerating them using today's
        # build environment defaults or requiring the old run/artifact APIs.
        if (identity['source_sha'] != sha or identity['tag'] != tag
                or identity['activation_allowed'] is not False
                or f"relayforge-{identity['pkgver']}-1-x86_64.pkg.tar.zst" != package
                or lifecycle['source_sha'] != sha or lifecycle['package'] != package
                or lifecycle['sha256'] != sums[package] or lifecycle['lifecycle'] != 'PASS'):
            raise ValueError('authenticated release metadata mismatch')


def all_releases():
    pages = json.loads(command('gh', 'api', '--paginate', '--slurp', f'repos/{REPO}/releases?per_page=100'))
    return [r for page in pages for r in page]


def merge_narrative(sha, get=api):
    for pr in get(f'commits/{sha}/pulls'):
        if pr['merged_at'] and pr['merge_commit_sha'] == sha and pr['base']['ref'] == 'main':
            body = pr.get('body') or ''
            heading = '## Problem and resulting behavior\n'
            if heading not in body:
                raise ValueError('reviewed PR narrative required for release notes')
            text = body.split(heading, 1)[1].split('\n## ', 1)[0].strip()
            if not 80 <= len(text) <= 12000:
                raise ValueError('reviewed release narrative missing or excessive')
            return text + f"\n\nReviewed change: {pr['html_url']}"
    raise ValueError('merged PR narrative unavailable')


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
    extra = verify_tunnel(directory, sha, identity, lifecycle, sums)
    extra = extra | verify_ubuntu_release(directory, sha)
    record = {'schema_version': 1, 'source_sha': sha, 'build_sha': sha,
              'package': expected, 'package_sha256': sums[expected], 'required_runs': runs,
              'run_urls': [f'https://github.com/{REPO}/actions/runs/{r}' for r in runs.values()],
              'arch_image': 'archlinux/archlinux@sha256:676f4d5b2cacc259ab30b1e871a272bd4a2e023a901f725fb1b12c84dc355f10',
              'arch_snapshot': '2026/09/25', 'live_acceptance': False}
    (directory / 'release.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    names = (ASSETS - {'SHA256SUMS'}) | {expected} | extra
    # Output only distributable files; operational source TARs stay CI evidence.
    checksums = ''.join(f'{hashlib.sha256((directory / n).read_bytes()).hexdigest()}  {n}\n' for n in sorted(names))
    (directory / 'SHA256SUMS').write_text(checksums)
    return identity, names | {'SHA256SUMS'}


def tag_commit(tag, get=api):
    """Resolve the remote ref, peeling annotated tags to a commit, with a bound."""
    ref = get(f'git/ref/tags/{tag}')
    if ref['ref'] != f'refs/tags/{tag}':
        raise ValueError('existing tag ref conflict')
    obj = ref['object']
    seen = set()
    for _ in range(16):
        if not re.fullmatch('[0-9a-f]{40}', obj['sha']):
            raise ValueError('invalid tag object identity')
        if obj['type'] == 'commit':
            return obj['sha']
        if obj['type'] != 'tag' or obj['sha'] in seen:
            raise ValueError('tag does not resolve to a commit')
        seen.add(obj['sha'])
        annotated = get(f"git/tags/{obj['sha']}")
        if annotated['sha'] != obj['sha']:
            raise ValueError('annotated tag identity conflict')
        obj = annotated['object']
    raise ValueError('tag chain exceeds verification bound')


def verify_draft_uploaded(directory, names, release, sha, tag, get=api):
    """Check a private partial draft by GitHub's stored asset digests, never by a tag lookup."""
    if (release.get('draft') is not True or type(release.get('id')) is not int
            or release['tag_name'] != tag or release['target_commitish'] != sha):
        raise ValueError('draft release source/identity conflict')
    if tag_commit(tag, get) != sha:
        raise ValueError('draft release tag target conflict')
    assets = release['assets']
    if len(assets) != len(names) or {a['name'] for a in assets} != names:
        raise ValueError('draft release asset inventory mismatch')
    for asset in assets:
        data = (directory / asset['name']).read_bytes()
        expected = 'sha256:' + hashlib.sha256(data).hexdigest()
        if (type(asset.get('id')) is not int or type(asset.get('size')) is not int
                or asset['size'] != len(data) or asset.get('digest') != expected):
            raise ValueError('draft release asset digest mismatch')


def verify_existing(directory, names, release, sha, tag, get=api):
    if release['tag_name'] != tag or release['target_commitish'] != sha:
        raise ValueError('existing release source conflict')
    assets = release['assets']
    if len(assets) != len(names) or {a['name'] for a in assets} != names:
        raise ValueError('existing immutable asset inventory differs; no overwrite')
    if tag_commit(tag, get) != sha:
        raise ValueError('existing immutable tag commit conflict')
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
    narrative = merge_narrative(sha)
    identity, names = release_files(directory, sha, runs)
    tag = identity['tag']
    expected_tag, package = source_names(sha)
    if tag != expected_tag or names != ASSETS | {package} | tunnel_assets(sha) | ubuntu_assets(sha):
        raise ValueError('tested artifact source naming mismatch')
    verify_provenance(directory)
    # A source SHA must be in protected-by-process main history, even if newer main exists.
    comparison = api(f'compare/{sha}...main')
    if comparison['status'] not in ('ahead', 'identical') or comparison['merge_base_commit']['sha'] != sha:
        raise ValueError('source no longer belongs to main history')
    # Do not depend on GitHub setting immutability to avoid our own overwrites.
    releases = all_releases()
    claims = [r for r in releases if r['tag_name'] == tag or r['target_commitish'] == sha]
    if len(claims) > 1:
        raise ValueError('conflicting release identities; owner reconciliation required')
    existing = claims[0] if claims else None
    if existing:
        if existing['draft']:
            # A prior partial write is recoverable only using the same tested
            # bytes, signed local manifest, exact tag/commit and GH-stored digests.
            fresh = api(f"releases/{existing['id']}")
            verify_draft_uploaded(directory, names, fresh, sha, tag)
            completed = api(f"releases/{fresh['id']}", '-X', 'PATCH', '-F', 'draft=false')
            if (completed['id'] != fresh['id'] or completed['draft'] is not False
                    or completed['tag_name'] != tag):
                raise ValueError('draft publication confirmation mismatch')
            verify_existing(directory, names, completed, sha, tag)
            print(f'recovered verified immutable release: {tag}')
            return
        verify_existing(directory, names, existing, sha, tag)
        print(f'exact immutable release already published: {tag}')
        return
    # Enforce monotonic Arch and SemVer order, not lexical short-SHA ordering.
    for release in releases:
        match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', release['tag_name'])
        if match and tuple(map(int, tag[1:].split('.'))) <= tuple(map(int, match.groups())):
            raise ValueError('release sequence must be strictly increasing')
    # Annotated tag; never move/reuse an existing ref. Partial failures retain evidence.
    tag_object = api('git/tags', '-X', 'POST', '-f', f'tag={tag}', '-f',
                     f'message=RelayForge {tag}; source {sha}; exact-head runs {json.dumps(runs, sort_keys=True)}',
                     '-f', f'object={sha}', '-f', 'type=commit')
    api('git/refs', '-X', 'POST', '-f', f'ref=refs/tags/{tag}', '-f', f"sha={tag_object['sha']}")
    notes = directory / 'notes.md'
    notes.write_text(f'''RelayForge {tag} — verified Linux packages (see attached target inventory).

{narrative}

Installation and operator action: pacman owns the binaries and inactive HTTP
and restricted tunnel user-unit templates. The optional tunnel-client package has
its own upstream version and verified provenance. Install/update/remove does not authorize service activation
or erase user credentials.

Source/build: `{sha}`. Exact-head required CI: {record_urls(runs)}.
Verify SHA256SUMS and source.json before `pacman -U`. Read the included Arch
packaging guide for explicit local setup, migration, downgrade and removal.
Downgrade restores package-owned files only; it is not a live recovery receipt.
User-data purge requires a separate reviewed plan and terminal confirmation.

Compatibility: provisional 0.1 source protocol; no general shell, automatic
deployment or live readiness claim. Physical authenticated tunnel/recovery gates
remain host-only. Existing Issue #89 evidence is not retroactively accepted.
Ubuntu 24.04 amd64 packages, when required by the source matrix, have separate
installed verification receipts. Verify the signed checksum inventory before
installing with apt; see the Ubuntu packaging guide. No service activation or
Ubuntu tunnel-client installation is authorized. Arch snapshot/toolchain details and CI
provenance are attached. These are CI-tested bytes, not reproducible-build proof.
''')
    subprocess.run(['gh', 'release', 'create', tag, '--repo', REPO, '--target', sha,
                    '--verify-tag', '--draft', '--title', f'RelayForge {tag}', '--notes-file', str(notes),
                    *[str(directory / n) for n in sorted(names)]], check=True)
    # GET /releases/tags/{tag} may 404 for drafts even when the draft and tag
    # exist; list by immutable identity and re-read the stable release ID.
    matches = [r for r in all_releases() if r['tag_name'] == tag
               or r['target_commitish'] == sha]
    if len(matches) != 1 or matches[0]['draft'] is not True:
        raise ValueError('new draft release missing or ambiguous')
    draft = api(f"releases/{matches[0]['id']}")
    verify_draft_uploaded(directory, names, draft, sha, tag)
    published = api(f"releases/{draft['id']}", '-X', 'PATCH', '-F', 'draft=false')
    if (published['id'] != draft['id'] or published['draft'] is not False
            or published['tag_name'] != tag):
        raise ValueError('draft publication confirmation mismatch')
    verify_existing(directory, names, published, sha, tag)


def record_urls(runs):
    return ', '.join(f'https://github.com/{REPO}/actions/runs/{r}' for r in runs.values())


def download_tested(destination, sha, runs):
    subprocess.run(['gh', 'run', 'download', str(runs['rdc-independent.yml']), '--repo', REPO,
                    '--name', f'relayforge-arch-source-{sha}', '--dir', str(destination)], check=True)
    if ubuntu_assets(sha):
        with tempfile.TemporaryDirectory(prefix='relayforge-ubuntu-') as tmp:
            subprocess.run(['gh', 'run', 'download', str(runs['rdc-independent.yml']), '--repo', REPO,
                            '--name', f'relayforge-ubuntu-verified-{sha}', '--dir', tmp], check=True)
            for path in Path(tmp).iterdir():
                name = {'source.json': 'ubuntu-source.json',
                        'SHA256SUMS': 'ubuntu-SHA256SUMS'}.get(path.name, path.name)
                if name not in ubuntu_assets(sha) or not path.is_file() or path.is_symlink():
                    raise ValueError('unexpected Ubuntu artifact inventory')
                (destination / name).write_bytes(path.read_bytes())
    # Validate actual tested bytes before any provenance publication.
    (destination / 'BUILD-SHA256SUMS').write_bytes((destination / 'SHA256SUMS').read_bytes())
    release_files(destination, sha, runs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['gate', 'download', 'publish'])
    parser.add_argument('--sha', required=True)
    parser.add_argument('--directory', type=Path, default=Path('dist'))
    args = parser.parse_args()
    if os.environ.get('GITHUB_REPOSITORY') != REPO or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_run':
        raise SystemExit('trusted workflow_run context required')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())['workflow_run']
    if (event['event'] != 'push' or event['head_branch'] != 'main' or event['head_sha'] != args.sha
            or event['repository']['full_name'] != REPO):
        raise SystemExit('only exact-source main push may release')
    if args.command == 'gate':
        plan = release_plan(args.sha, event)
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(f'ready={str(bool(plan)).lower()}\n')
            output.write('plan=' + json.dumps(plan, separators=(',', ':')) + '\n')
    else:
        plan = json.loads(os.environ['RELEASE_PLAN'])
        if not plan or len(plan) > 100:
            raise SystemExit('bounded approved release plan required')
        for item in plan:
            sha = item['sha']
            runs = accepted_runs(sha)
            if not runs or runs['rdc-independent.yml'] != item['run_id'] or not accepted_merge(sha):
                raise SystemExit('exact-head CI/review changed; publication refused')
            destination = args.directory / sha
            if args.command == 'download':
                download_tested(destination, sha, runs)
            else:
                # Re-download step already generated release metadata; original
                # build checksums are retained to verify tested inputs again.
                (destination / 'SHA256SUMS').write_bytes((destination / 'BUILD-SHA256SUMS').read_bytes())
                publish(destination, sha, runs)
