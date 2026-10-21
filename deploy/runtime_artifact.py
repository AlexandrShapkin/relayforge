"""Read-only artifact/activation-plan validation. NEVER installs, selects or restarts.

A manifest/receipt is evidence metadata, not operator authority or a signed
attestation. Expected commit/digest pins must come from independently reviewed
CI/operator evidence. Activation remains the separate local procedure in docs.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat


class ArtifactError(Exception):
    pass


@contextmanager
def opened(path):
    """Pin every path component; never follow input symlinks or block on FIFOs."""
    path = Path(path)
    if not path.is_absolute() or any(p == ".." for p in path.parts):
        raise ArtifactError("absolute artifact path required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    try:
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        meta = os.fstat(descriptor)
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o022:
            raise ArtifactError("unsafe artifact file")
        yield descriptor, meta
    except OSError as exc:
        raise ArtifactError("artifact unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def document(path):
    with opened(path) as (fd, meta):
        if meta.st_size > 4096:
            raise ArtifactError("metadata too large")
        raw = os.read(fd, 4097)
        if len(raw) > 4096:
            raise ArtifactError("metadata too large")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate metadata key")
                result[key] = value
            return result
        result = json.loads(raw, object_pairs_hook=unique)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError) as exc:
        raise ArtifactError("invalid artifact metadata") from exc


def pins(commit, digest):
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ArtifactError("full lowercase commit SHA and SHA-256 required")


def verify(binary, manifest, commit, digest):
    pins(commit, digest)
    record = document(manifest)
    if type(record.get("schema_version")) is not int or record != {"schema_version": 1, "commit": commit, "sha256": digest, "binary": "relayforge-mcp"}:
        raise ArtifactError("artifact manifest/pin mismatch")
    with opened(binary) as (fd, before):
        if before.st_size > 128 * 1024 * 1024 or not before.st_mode & 0o111:
            raise ArtifactError("invalid executable artifact")
        computed = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > 128 * 1024 * 1024:
                raise ArtifactError("artifact too large")
            computed.update(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ArtifactError("artifact changed during verification")
        if computed.hexdigest() != digest:
            raise ArtifactError("artifact digest mismatch")
    return {"commit": commit, "sha256": digest, "artifact_id": f"{commit}-{digest}"}


def activation_plan(candidate, rollback, rollback_receipt):
    if candidate["artifact_id"] == rollback["artifact_id"]:
        raise ArtifactError("distinct verified rollback required")
    receipt = document(rollback_receipt)
    if receipt.get("restricted_worker_ok") is not True or receipt.get("live_health_ok") is not True or receipt != {"commit": rollback["commit"], "sha256": rollback["sha256"],
                   "restricted_worker_ok": True, "live_health_ok": True}:
        raise ArtifactError("verified rollback receipt required")
    return {"candidate": candidate, "rollback": rollback, "operator_approval_required": True,
            "actions_performed": [], "procedure": "docs/runtime-artifacts.md"}


def verify_installed(binary):
    """Only for a migrated, frozen artifact. Never guesses a historical baseline."""
    binary = Path(binary)
    # current is the one intentional, operator-managed directory symlink.
    store = binary.parent.parent
    try:
        for path in [store, store / "artifacts"]:
            meta = path.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o022:
                raise ArtifactError("unsafe runtime store")
        target = os.readlink(store / "current")
        if not re.fullmatch(r"artifacts/[0-9a-f]{40}-[0-9a-f]{64}", target):
            raise ArtifactError("invalid runtime selector")
        commit, digest = target.split('/')[1].split('-')
        selected = store / target / "relayforge-mcp"
        with opened(selected) as (_, meta):
            if meta.st_mode & 0o222:
                raise ArtifactError("runtime artifact must be frozen")
        verify(selected, selected.with_name("manifest.json"), commit, digest)
        return selected
    except OSError as exc:
        raise ArtifactError("runtime store unavailable") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["verify", "plan"])
    for prefix in ["", "rollback-"]:
        for name in ["binary", "manifest", "commit", "sha256"]:
            parser.add_argument("--" + prefix + name, required=not prefix)
    parser.add_argument("--rollback-receipt")
    args = parser.parse_args(argv)
    try:
        candidate = verify(args.binary, args.manifest, args.commit, args.sha256)
        if args.operation == "verify":
            result = {"verified": candidate, "actions_performed": []}
        else:
            if not all([args.rollback_binary, args.rollback_manifest, args.rollback_commit, args.rollback_sha256, args.rollback_receipt]):
                raise ArtifactError("explicit verified rollback and receipt required")
            rollback = verify(args.rollback_binary, args.rollback_manifest, args.rollback_commit, args.rollback_sha256)
            result = activation_plan(candidate, rollback, args.rollback_receipt)
        print(json.dumps(result))
        return 0
    except (ArtifactError, TypeError) as exc:
        print(json.dumps({"ok": False, "reason": str(exc), "actions_performed": []}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
