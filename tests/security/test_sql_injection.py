"""Security regression test — CWE-89 SQL injection in `app.db.search_findings`.

╔══════════════════════════════════════════════════════════════════════════════╗
║  THIS FILE IS EXPECTED TO FAIL ON `main`.                                    ║
║                                                                              ║
║  `search_findings` interpolates the search term straight into the SQL text  ║
║  instead of binding it, so the findings search box (`GET /api/findings?      ║
║  search=`) is injectable.  These tests assert the *fixed* behaviour, so they ║
║  are RED on the seeded commit and GREEN once the query is parameterised.     ║
║                                                                              ║
║      pytest -m security     on main          →  FAIL   (injectable)          ║
║      pytest -m security     on the patch     →  PASS   (bound parameters)    ║
║                                                                              ║
║  The intended fix is a two-line swap to `db._search_findings_safe`, which is ║
║  already written and unused in app/db.py.                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import pytest

from app import db

pytestmark = pytest.mark.security


def _seed_two(engine, make_finding) -> None:
    """Two findings whose title/package contain neither the tautology nor 'nomatch'."""
    db.upsert_findings(
        engine,
        [
            make_finding(vuln_id="CVE-A", title="zlib buffer overflow",
                         package_name="zlib1g", fingerprint="fp-a"),
            make_finding(vuln_id="CVE-B", title="openssl session bug",
                         package_name="libssl3", fingerprint="fp-b"),
        ],
        job_run_id="test-run",
    )


def test_tautology_payload_does_not_return_every_row(engine, make_finding):
    """`x' OR '1'='1' --` must not turn a search into "select everything".

    On the seeded code the interpolated term makes the WHERE clause always true and all
    rows come back; a parameterised query treats the whole string as a literal to search
    for, matches nothing, and returns zero rows.
    """
    _seed_two(engine, make_finding)

    injected = db.search_findings(engine, "nomatch' OR '1'='1' --")

    assert injected == [], (
        f"SQL injection succeeded — a tautology payload returned {len(injected)} row(s). "
        "app/db.py:search_findings interpolates the search term instead of binding it "
        "(CWE-89). Route it through the parameterised _search_findings_safe."
    )


def test_union_select_cannot_exfiltrate(engine, make_finding):
    """A UNION payload must not append attacker-chosen rows to the result set."""
    _seed_two(engine, make_finding)

    injected = db.search_findings(
        engine, "nomatch' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,"
                "NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
    )

    assert injected == [], (
        "SQL injection: a UNION SELECT payload returned rows. The search term reaches the "
        "SQL text unescaped in app/db.py:search_findings."
    )


def test_api_findings_search_is_not_injectable(client, engine, make_finding):
    """The same defect through the HTTP surface the React app calls."""
    _seed_two(engine, make_finding)

    body = client.get("/api/findings?search=nomatch%27%20OR%20%271%27%3D%271%27%20--").get_json()

    assert body["count"] == 0, (
        f"GET /api/findings?search= is SQL-injectable — a tautology returned {body['count']} "
        "row(s). The search box is a live CWE-89 sink."
    )


def test_legitimate_search_still_works(engine, make_finding):
    """Green-path companion: the fix must not be "refuse every search".

    A patch that parameterises the query but also breaks ordinary search would pass the
    three tests above and fail this one — which is not a fix.
    """
    _seed_two(engine, make_finding)

    hits = db.search_findings(engine, "openssl")

    assert len(hits) == 1
    assert hits[0]["package_name"] == "libssl3"
