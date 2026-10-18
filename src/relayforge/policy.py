"""Fail-closed authorization for narrowly scoped agent capabilities."""
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Grant:
    actor: str
    device: str
    capability: str


class Policy:
    """Explicit grants only. No implicit wildcard or inherited permissions."""

    def __init__(self, grants=()):
        self._grants = frozenset(grants)

    def allows(self, actor: str, device: str, capability: str) -> bool:
        if not all(isinstance(x, str) and x and x.strip() == x for x in (actor, device, capability)):
            return False
        return Grant(actor, device, capability) in self._grants


def confined_path(root: str, candidate: str) -> bool:
    """Lexical prefilter only; agent must additionally use symlink-safe file APIs."""
    if not isinstance(root, str) or not isinstance(candidate, str):
        return False
    if not root.startswith('/') or not candidate.startswith('/'):
        return False
    if '\\x00' in root or '\\x00' in candidate or '..' in candidate.split('/'):
        return False
    base, target = PurePosixPath(root), PurePosixPath(candidate)
    return base == target or base in target.parents
