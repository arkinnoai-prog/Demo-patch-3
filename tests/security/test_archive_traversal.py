"""Security regression test — CWE-22 path traversal in `app.jobs.archive`.

╔══════════════════════════════════════════════════════════════════════════════╗
║  THIS FILE IS EXPECTED TO FAIL ON `main`.                                    ║
║                                                                              ║
║  Everything here is marked `@pytest.mark.security` and excluded from the     ║
║  default pytest run (see pyproject.toml `addopts`).  That is not a way to    ║
║  hide a failure — it is the mechanism that makes the failure *evidence*.     ║
║                                                                              ║
║  POC-PLAN.md §6 step 2: a `verify-vulnerable` job runs the generated         ║
║  security test against the PRE-PATCH commit.  A recorded red-then-green      ║
║  transition is genuine proof the patch works, and it catches the failure     ║
║  mode where the AI writes a test that passes trivially.                      ║
║                                                                              ║
║      pytest -m security     on main          →  FAIL   (vulnerable)          ║
║      pytest -m security     on the patch     →  PASS   (fixed)               ║
║                                                                              ║
║  `ci.yml`'s verify-vulnerable job asserts BOTH halves.  A security test that ║
║  passes on the pre-patch commit fails the build, because it proves nothing.  ║
╚══════════════════════════════════════════════════════════════════════════════╝

The intended patch is in .baobao/patch-targets.md §4.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.jobs.archive import ArchiveError, extract_bundle

pytestmark = pytest.mark.security


def test_relative_traversal_is_refused(tmp_path: Path, make_tar):
    """A `../` member must not be written outside the extraction root.

    This is the exploit in its simplest form: a scanner artifact bundle — which comes
    from a CI job that, in a real estate, may itself be attacker-influenced — declares
    a member path that climbs out of the directory it is extracted into.
    """
    dest = tmp_path / "extract"
    outside = tmp_path / "pwned.txt"
    bundle = make_tar("evil.tar.gz", [
        ("report.json", "{}"),
        ("../pwned.txt", "owned by the archive"),
    ])

    with pytest.raises(ArchiveError):
        extract_bundle(bundle, dest)

    assert not outside.exists(), (
        f"path traversal succeeded — {outside} was written outside {dest}. "
        "This is the seeded CWE-22 in app/jobs/archive.py:extract_bundle."
    )


def test_deep_traversal_is_refused(tmp_path: Path, make_tar):
    """Multi-level traversal, the form used to reach `/etc/cron.d` or `~/.ssh`."""
    dest = tmp_path / "a" / "b" / "extract"
    outside = tmp_path / "escaped.txt"
    bundle = make_tar("evil-deep.tar.gz", [("../../../escaped.txt", "escaped")])

    with pytest.raises(ArchiveError):
        extract_bundle(bundle, dest)

    assert not outside.exists()


def test_absolute_paths_are_refused(tmp_path: Path, make_tar):
    """An absolute member path must be refused, not silently re-rooted.

    Python's tarfile strips a leading `/` on extraction, so this one does not escape on
    its own — but a fix that only checks for `..` and lets absolute members through has
    not understood the bug.  The guard must reject the member.
    """
    dest = tmp_path / "extract"
    bundle = make_tar("evil-abs.tar.gz", [("/tmp/baobao-absolute.txt", "absolute")])

    with pytest.raises(ArchiveError):
        extract_bundle(bundle, dest)


def test_the_guard_does_not_break_legitimate_bundles(tmp_path: Path, make_tar):
    """Green-path companion.

    Without this, "fix the traversal" could be satisfied by refusing every archive.
    A patch that passes the three tests above and fails this one is not a fix.
    """
    dest = tmp_path / "extract"
    bundle = make_tar("ok.tar.gz", [
        ("run-128/trivy/report.json", '{"SchemaVersion": 2}'),
        ("run-128/meta.txt", "ok"),
    ])

    written = extract_bundle(bundle, dest)

    assert len(written) == 2
    assert (dest / "run-128" / "trivy" / "report.json").is_file()
