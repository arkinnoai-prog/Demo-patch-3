"""Extraction of scanner-artifact bundles.

CI uploads scanner output as a tar bundle (`actions/upload-artifact` content, or a
`trivy` run's artifact directory).  A manifest source with an `archive:` key points at
one, and the named `member:` inside it is parsed.

┌──────────────────────────────────────────────────────────────────────────────┐
│ ⚠️  SEEDED VULNERABILITY — CWE-22 path traversal (the CVE-2007-4559 pattern). │
│                                                                              │
│ `extract_bundle` calls `TarFile.extractall()` with no member validation.  A  │
│ tar entry named `../../etc/cron.d/x` — or an absolute path, or a symlink     │
│ pointing outside the tree — is written wherever it says, outside the         │
│ extraction root.  Bandit flags this as B202; CodeQL as py/tarslip.           │
│                                                                              │
│ This is the ONE reachable code-level vulnerability seeded in this repo, and  │
│ the only one here that can be PROVEN exploited by a test.  That makes it the │
│ red-then-green evidence artifact described in POC-PLAN.md §6:                │
│                                                                              │
│   tests/security/test_archive_traversal.py  — RED on this commit,            │
│                                              GREEN once patched.             │
│                                                                              │
│ Expected remediation channel: ai_code_fix (SAST → mandatory human review,    │
│ POC-PLAN.md §7 guardrails).  The intended patch is in                        │
│ .baobao/patch-targets.md — `_is_within` below is already written and unused, │
│ so the fix is small enough to review in one screen.                          │
└──────────────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import tarfile
from pathlib import Path

MAX_MEMBERS = 2000
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MiB — zip-bomb ceiling


class ArchiveError(ValueError):
    """Raised when a bundle is unusable or refuses to extract."""


def _is_within(root: Path, candidate: Path) -> bool:
    """True when `candidate` resolves inside `root`.

    The guard the seeded vulnerability is missing.  Kept here, correct and tested
    (`tests/unit/test_archive.py`), so the patch is a three-line change rather than a
    rewrite — which is what keeps the AI patch's diff small enough to score highly on
    confidence (POC-PLAN.md §7).
    """
    try:
        root_resolved = root.resolve()
        candidate_resolved = candidate.resolve()
    except OSError:
        return False
    return root_resolved == candidate_resolved or root_resolved in candidate_resolved.parents


def _check_size(archive: tarfile.TarFile) -> None:
    """Reject obviously hostile bundles before writing anything to disk."""
    members = archive.getmembers()
    if len(members) > MAX_MEMBERS:
        raise ArchiveError(f"bundle has {len(members)} members, limit is {MAX_MEMBERS}")
    total = sum(m.size for m in members)
    if total > MAX_UNCOMPRESSED_BYTES:
        raise ArchiveError(f"bundle expands to {total} bytes, limit is {MAX_UNCOMPRESSED_BYTES}")


def extract_bundle(bundle_path: Path, dest_dir: Path) -> list[Path]:
    """Extract a scanner-artifact bundle into `dest_dir` and return the files written.

    ⚠️  VULNERABLE — see the module docstring.  `extractall` here honours whatever paths
    the tar declares, including `../` traversal and absolute paths.
    """
    bundle_path = Path(bundle_path)
    dest_dir = Path(dest_dir)

    if not bundle_path.is_file():
        raise ArchiveError(f"bundle not found: {bundle_path}")

    dest_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(bundle_path, "r:*") as archive:
            _check_size(archive)

            # --- BEGIN SEEDED VULNERABILITY (CWE-22) ---------------------------
            # No member path is validated against `dest_dir` before extraction.
            # The fix is to filter members through `_is_within` (Python ≥3.12 also
            # offers `filter="data"`).  See .baobao/patch-targets.md.
            #
            # No `# nosec` here on purpose: Bandit MUST report B202 and CodeQL
            # py/tarslip — that finding is the whole point of this seed.  (ruff's S202
            # is silenced for this file in pyproject.toml so the repo's own linter
            # stays usable; that does not affect Bandit or CodeQL.)
            archive.extractall(path=dest_dir)
            # --- END SEEDED VULNERABILITY --------------------------------------

            names = [m.name for m in archive.getmembers() if m.isfile()]
    except tarfile.TarError as exc:
        raise ArchiveError(f"could not read bundle {bundle_path}: {exc}") from exc

    return [dest_dir / name for name in names]


def read_member(bundle_path: Path, member: str, work_dir: Path) -> Path:
    """Extract a bundle and return the path to the requested member."""
    extracted = extract_bundle(bundle_path, work_dir)

    wanted = Path(work_dir) / member
    if wanted.is_file():
        return wanted

    # Fall back to a basename match — CI bundles are often nested under a run directory.
    target_name = Path(member).name
    for path in extracted:
        if path.name == target_name and path.is_file():
            return path

    raise ArchiveError(f"member {member!r} not found in {bundle_path}")
