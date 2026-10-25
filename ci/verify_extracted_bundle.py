#!/usr/bin/env python3
"""Verify and execute portable tests from the produced offline Arch source bundle.

This operates only in a disposable checkout. It never installs or activates
anything and uses no host credentials, local grants, or production services.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import source_package


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_extracted_bundle.py ARCHIVE EXACT_HEAD")
    archive = Path(sys.argv[1]).resolve()
    head = sys.argv[2]
    actual_head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if head != actual_head:
        raise RuntimeError("archive verification requires exact checkout HEAD")

    # Strict archive verification runs *before* reading any TAR entry via tarfile.
    # The archive must remain unchanged throughout extraction.
    with archive.open("rb") as stream:
        digest_before = hashlib.file_digest(stream, "sha256").hexdigest()
    source_package.verify(archive, head)
    names = set(source_package.SOURCES) | {
        "bin/relayforge-mcp", "manifest.json", "package.json", "seal.json"
    }
    with tempfile.TemporaryDirectory(prefix="arch-bundle-", dir=ROOT / ".build") as tmp:
        root = Path(tmp)
        seen = set()
        with tarfile.open(archive, "r:gz") as package:
            for entry in package:
                if (entry.name not in names or entry.name in seen
                        or not entry.isfile()):
                    raise RuntimeError("unexpected archive entry")
                seen.add(entry.name)
                path = root / entry.name
                path.parent.mkdir(parents=True, exist_ok=True)
                reader = package.extractfile(entry)
                if reader is None:
                    raise RuntimeError("missing archive body")
                # All sizes and inventory were bounded by source_package.verify.
                body = reader.read(entry.size + 1)
                if len(body) != entry.size:
                    raise RuntimeError("archive entry changed during extraction")
                path.write_bytes(body)
                path.chmod(entry.mode)
                if entry.name in source_package.SOURCES:
                    committed = subprocess.check_output(
                        ["git", "show", f"{head}:{entry.name}"], cwd=ROOT
                    )
                    if committed != body:
                        raise RuntimeError("extracted source differs from exact HEAD")
        if seen != names:
            raise RuntimeError("incomplete archive")
        with archive.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest_before:
                raise RuntimeError("archive changed during extraction")
        # Run the suites in the *extracted* tree, not in the checkout.
        suites = sorted(name for name in source_package.SOURCES
                        if name.startswith("scripts/test_") and name.endswith(".py"))
        if not suites:
            raise RuntimeError("no portable test suites packaged")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        for path in suites:
            subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s",
                 "scripts", "-p", Path(path).name],
                cwd=root, env=env, check=True,
            )
        print(f"verified extracted Arch bundle: {head}, {len(suites)} suites")


if __name__ == "__main__":
    main()
