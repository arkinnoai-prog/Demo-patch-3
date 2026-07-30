"""Guards on the seeded state itself.

A demo target repo has an unusual failure mode: someone tidies up, the vulnerabilities
disappear, and the pipeline finds nothing on stage.  These tests assert the seeds are
still present, so that a well-meaning cleanup breaks the build instead of the demo.

These are the mirror image of `test_archive_traversal.py`: they PASS on `main` and FAIL
once a patch lands.  That is why they carry their own `seed` marker rather than
`security` — `pytest -m security` has to be able to go green on a patch branch, and it
could not if a seed-still-present check ran alongside it.

    pytest -m seed        GREEN on main · RED on a patch branch (expected)
    pytest -m security    RED on main   · GREEN on a patch branch (the evidence)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.seed

REPO_ROOT = Path(__file__).resolve().parents[2]
SEED = json.loads((REPO_ROOT / ".baobao" / "seed.json").read_text(encoding="utf-8"))


def _seed(seed_id: str) -> dict:
    return next(s for s in SEED["seeds"] if s["id"] == seed_id)


def test_dockerfile_still_pins_the_vulnerable_base_image():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    expected = _seed("base-image")["current"]
    assert f"FROM {expected}" in dockerfile, (
        f"the seeded base image {expected} is gone from the Dockerfile — "
        "CVE scenario 3 has no finding to raise. Run scripts/reseed.py."
    )


def test_requirements_still_pin_the_vulnerable_versions():
    requirements = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
    missing = []
    for package in _seed("pip-pins")["packages"]:
        # No `$` anchor — every pin carries a trailing `# CVE-…` comment.
        if not re.search(rf"^{re.escape(package['name'])}=={re.escape(package['pinned'])}\s*(#|$)",
                         requirements, re.MULTILINE | re.IGNORECASE):
            missing.append(f"{package['name']}=={package['pinned']}")

    assert not missing, f"seeded pins were bumped outside the patch pipeline: {missing}"


def test_the_unreachable_dependency_is_still_unreachable():
    """Scenario 7's premise.

    If someone imports Pygments, the finding stops being a false positive and the risk
    acceptance becomes wrong.  Cheaper to catch here than on stage.
    """
    package = _seed("unreachable-dep")["package"].lower()
    offenders = [
        path.relative_to(REPO_ROOT)
        for path in (REPO_ROOT / "app").rglob("*.py")
        if re.search(rf"^\s*(import|from)\s+{package}\b",
                     path.read_text(encoding="utf-8"), re.MULTILINE | re.IGNORECASE)
    ]
    assert not offenders, (
        f"{package} is now imported by {offenders} — it is reachable, so CVE scenario 7 "
        "(false positive / risk-accepted) no longer applies to it."
    )


def test_the_traversal_sink_is_still_present():
    source = (REPO_ROOT / "app" / "jobs" / "archive.py").read_text(encoding="utf-8")
    assert "extractall(path=dest_dir)" in source, (
        "the seeded CWE-22 has been fixed on main. That is fine once the demo has been "
        "recorded — but reseed before the next run, or there is no red-then-green."
    )


def test_the_sql_injection_sink_is_still_present():
    source = (REPO_ROOT / "app" / "db.py").read_text(encoding="utf-8")
    assert "LIKE '%{term}%'" in source, (
        "the seeded CWE-89 in app/db.py:search_findings has been parameterised on main. "
        "That is fine once the demo has been recorded — but reseed before the next run, "
        "or the findings search box is no longer a SQL-injection finding for the pipeline."
    )


def test_the_additional_code_sinks_are_still_present():
    """The extra seeded findings for the full-stack demo: SSRF, insecure TLS, hardcoded
    credential and Flask debug.  Like the pins, they PASS on main and fail once patched."""
    present = {
        "app/jobs/runner.py": "requests.get(source.url",   # SSRF        (CWE-918)
        "app/jobs/report.py": "verify=False",              # insecure TLS (CWE-295)
        "app/cli.py": "debug=True",                        # Flask debug (CWE-489)
    }
    for rel, needle in present.items():
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert needle in source, f"seeded sink {needle!r} is gone from {rel}; reseed or git revert."

    report = (REPO_ROOT / "app" / "jobs" / "report.py").read_text(encoding="utf-8")
    assert "_DEV_FALLBACK_TOKEN" in report and "baobao_pat_" in report, (
        "the seeded hardcoded credential (CWE-798) is gone from app/jobs/report.py."
    )


def test_the_seed_manifest_matches_the_scenario_matrix():
    # POC-PLAN.md §2 assigns scenario 3 to this repo; §1 assigns Container Apps.
    assert SEED["primaryScenario"] == 3
    assert SEED["azureService"] == "Container Apps job"
    assert {s["id"] for s in SEED["scenarios"]} == {3, 7}
