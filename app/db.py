"""Persistence.

SQLAlchemy Core with hand-written SQL rather than an ORM, for two reasons: the whole
schema is two tables, and PostgreSQL is the one database everywhere — the dev server from
docker-compose locally and in CI, the shared Azure PostgreSQL Flexible Server in the
estate — so there is no dialect to abstract over.

`INSERT … ON CONFLICT DO UPDATE` (Postgres ≥9.5) is what the dedupe upsert relies on.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from app.models import Finding, JobRun, utcnow

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS job_runs (
        id                TEXT PRIMARY KEY,
        name              TEXT NOT NULL,
        environment       TEXT NOT NULL,
        started_at        TEXT NOT NULL,
        finished_at       TEXT,
        status            TEXT NOT NULL,
        sources           INTEGER NOT NULL DEFAULT 0,
        findings_ingested INTEGER NOT NULL DEFAULT 0,
        findings_new      INTEGER NOT NULL DEFAULT 0,
        mechanical_ratio  REAL    NOT NULL DEFAULT 0,
        error             TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id                  TEXT PRIMARY KEY,
        fingerprint         TEXT NOT NULL UNIQUE,
        job_run_id          TEXT,
        repo                TEXT NOT NULL,
        source_scanner      TEXT NOT NULL,
        vuln_id             TEXT NOT NULL,
        severity            TEXT NOT NULL,
        package_name        TEXT,
        installed_version   TEXT,
        fixed_version       TEXT,
        title               TEXT,
        target              TEXT,
        target_class        TEXT,
        artifact_type       TEXT,
        cvss                REAL,
        primary_url         TEXT,
        remediation_channel TEXT NOT NULL,
        first_seen          TEXT NOT NULL,
        last_seen           TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings (repo)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_channel ON findings (remediation_channel)",
]

_UPSERT_FINDING = text(
    """
    INSERT INTO findings (
        id, fingerprint, job_run_id, repo, source_scanner, vuln_id, severity,
        package_name, installed_version, fixed_version, title, target, target_class,
        artifact_type, cvss, primary_url, remediation_channel, first_seen, last_seen
    ) VALUES (
        :id, :fingerprint, :job_run_id, :repo, :source_scanner, :vuln_id, :severity,
        :package_name, :installed_version, :fixed_version, :title, :target, :target_class,
        :artifact_type, :cvss, :primary_url, :remediation_channel, :first_seen, :last_seen
    )
    ON CONFLICT (fingerprint) DO UPDATE SET
        job_run_id          = excluded.job_run_id,
        severity            = excluded.severity,
        installed_version   = excluded.installed_version,
        fixed_version       = excluded.fixed_version,
        title               = excluded.title,
        cvss                = excluded.cvss,
        remediation_channel = excluded.remediation_channel,
        last_seen           = excluded.last_seen
    """
)


def new_id() -> str:
    return str(uuid.uuid4())


def _redact_url(url: str) -> str:
    """A DB URL with the password masked — safe to print into a CI log or an error."""
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    creds, host = rest.rsplit("@", 1)
    user = creds.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"


def create_db_engine(database_url: str) -> Engine:
    """Build a PostgreSQL engine.

    `pool_pre_ping` checks a pooled connection is still alive before handing it out, so a
    Postgres failover or an idle-timeout drop surfaces as one retry rather than an error.
    """
    return create_engine(database_url, future=True, pool_pre_ping=True)


def init_schema(engine: Engine) -> None:
    """Idempotent schema creation.  Two tables does not warrant a migration tool."""
    with engine.begin() as conn:
        for statement in _SCHEMA:
            conn.execute(text(statement))


@contextmanager
def session(engine: Engine) -> Iterator[Any]:
    with engine.begin() as conn:
        yield conn


def ping(engine: Engine) -> bool:
    """Readiness probe backing `GET /readyz`."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


# --- job runs --------------------------------------------------------------


def start_run(engine: Engine, name: str, environment: str) -> JobRun:
    run = JobRun(id=new_id(), name=name, environment=environment, started_at=utcnow())
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO job_runs (id, name, environment, started_at, status)
                VALUES (:id, :name, :environment, :started_at, :status)
                """
            ),
            {
                "id": run.id,
                "name": run.name,
                "environment": run.environment,
                "started_at": run.started_at,
                "status": run.status,
            },
        )
    return run


def finish_run(engine: Engine, run: JobRun) -> None:
    run.finished_at = run.finished_at or utcnow()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                UPDATE job_runs SET
                    finished_at       = :finished_at,
                    status            = :status,
                    sources           = :sources,
                    findings_ingested = :findings_ingested,
                    findings_new      = :findings_new,
                    mechanical_ratio  = :mechanical_ratio,
                    error             = :error
                WHERE id = :id
                """
            ),
            run.to_dict(),
        )


def list_runs(engine: Engine, limit: int = 20) -> list[dict[str, Any]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM job_runs ORDER BY started_at DESC LIMIT :limit"),
            {"limit": limit},
        )
        return [dict(row._mapping) for row in rows]


def get_run(engine: Engine, run_id: str) -> dict[str, Any] | None:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT * FROM job_runs WHERE id = :id"), {"id": run_id}
        ).first()
        return dict(row._mapping) if row else None


# --- findings --------------------------------------------------------------


def existing_fingerprints(engine: Engine, fingerprints: Iterable[str]) -> set:
    """Which of these we have seen before.

    Chunked because Postgres caps bind parameters at 65535 and a full estate scan can
    produce more findings than that in one run.
    """
    values = [f for f in fingerprints if f]
    if not values:
        return set()

    found: set = set()
    chunk_size = 500
    with engine.connect() as conn:
        for start in range(0, len(values), chunk_size):
            chunk = values[start : start + chunk_size]
            params = {f"f{i}": v for i, v in enumerate(chunk)}
            # The interpolated text is only `:f0, :f1, …` — generated bind-parameter
            # names, never scanner data.  Every value travels as a bound parameter.
            placeholders = ", ".join(f":{k}" for k in params)
            sql = (
                "SELECT fingerprint FROM findings "  # noqa: S608 - names generated, values bound
                f"WHERE fingerprint IN ({placeholders})"
            )
            rows = conn.execute(text(sql), params)
            found.update(row[0] for row in rows)
    return found


def upsert_findings(engine: Engine, findings: list[Finding], job_run_id: str) -> int:
    """Insert new findings, refresh `last_seen` on ones we already had.

    Returns the count of genuinely new findings — that is the number the dashboard's
    "new since last scan" figure is built from.
    """
    if not findings:
        return 0

    seen = existing_fingerprints(engine, [f.fingerprint for f in findings])
    new_count = 0

    with engine.begin() as conn:
        for finding in findings:
            is_new = finding.fingerprint not in seen
            if is_new:
                new_count += 1
            payload = finding.to_dict()
            payload["id"] = new_id()
            payload["job_run_id"] = job_run_id
            conn.execute(_UPSERT_FINDING, payload)

    return new_count


def query_findings(
    engine: Engine,
    repo: str = "",
    severity: str = "",
    channel: str = "",
    limit: int = 200,
) -> list[dict[str, Any]]:
    clauses = []
    params: dict[str, Any] = {"limit": limit}
    if repo:
        clauses.append("repo = :repo")
        params["repo"] = repo
    if severity:
        clauses.append("severity = :severity")
        params["severity"] = severity.upper()
    if channel:
        clauses.append("remediation_channel = :channel")
        params["channel"] = channel

    # `clauses` holds fixed literal fragments chosen by which arguments were supplied;
    # every user-supplied value is bound through `params`.  No request data reaches the
    # SQL text.  (Deliberate: the SQL-injection scenario belongs to baobao-payments-api,
    # and an accidental second one here would muddy which repo proves which path.)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        "SELECT * FROM findings "  # noqa: S608 - fixed fragments; values are all bound
        f"{where} "
        "ORDER BY CASE severity "
        "  WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
        "  WHEN 'LOW' THEN 3 ELSE 4 END, "
        "repo, package_name "
        "LIMIT :limit"
    )
    with engine.connect() as conn:
        return [dict(row._mapping) for row in conn.execute(text(sql), params)]


def search_findings(engine: Engine, term: str, limit: int = 200) -> list[dict[str, Any]]:
    """Free-text search over findings by title or package name.

    ┌────────────────────────────────────────────────────────────────────────────┐
    │ ⚠️  SEEDED VULNERABILITY — SQL injection (CWE-89).                          │
    │                                                                            │
    │ `term` is interpolated straight into the SQL string instead of travelling  │
    │ as a bound parameter, so a value like `x' OR '1'='1` changes the query's   │
    │ logic and `x' UNION SELECT ...--` reads arbitrary columns.  Bandit flags   │
    │ this as B608; CodeQL as py/sql-injection.                                  │
    │                                                                            │
    │ The fix is the same shape as every other query in this module: bind the    │
    │ value.  A parameterised version is written and unused just below           │
    │ (`_search_findings_safe`), so the patch is a two-line swap.                │
    └────────────────────────────────────────────────────────────────────────────┘
    """
    # --- BEGIN SEEDED VULNERABILITY (CWE-89) -------------------------------
    # `term` is concatenated into the SQL text.  No `# nosec`: Bandit and CodeQL
    # are meant to report this — that is the finding the pipeline ingests.
    sql = (
        "SELECT * FROM findings "  # noqa: S608 - seeded SQL injection, see docstring
        f"WHERE title LIKE '%{term}%' OR package_name LIKE '%{term}%' "
        "ORDER BY CASE severity "
        "  WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
        "  WHEN 'LOW' THEN 3 ELSE 4 END, "
        f"repo, package_name LIMIT {int(limit)}"
    )
    # --- END SEEDED VULNERABILITY ------------------------------------------
    with engine.connect() as conn:
        return [dict(row._mapping) for row in conn.execute(text(sql))]


def _search_findings_safe(engine: Engine, term: str, limit: int = 200) -> list[dict[str, Any]]:
    """The parameterised fix for `search_findings`.  Written, tested and unused, so the
    seeded CWE-89 patch is a small diff (the same red-then-green shape as the tar-slip
    seed in app/jobs/archive.py)."""
    like = f"%{term}%"
    sql = (
        "SELECT * FROM findings "
        "WHERE title LIKE :like OR package_name LIKE :like "
        "ORDER BY CASE severity "
        "  WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
        "  WHEN 'LOW' THEN 3 ELSE 4 END, "
        "repo, package_name LIMIT :limit"
    )
    with engine.connect() as conn:
        rows = conn.execute(text(sql), {"like": like, "limit": limit})
        return [dict(row._mapping) for row in rows]


def counts_by(engine: Engine, column: str) -> dict[str, int]:
    """Aggregate for `GET /metrics`.

    `column` cannot be a bind parameter — SQL does not allow one in a GROUP BY — so it
    is checked against a hardcoded allowlist before interpolation.  Anything else raises.
    """
    if column not in ("severity", "remediation_channel", "repo", "source_scanner"):
        raise ValueError(f"not an aggregatable column: {column}")
    with engine.connect() as conn:
        sql = (
            f"SELECT {column}, COUNT(*) "  # noqa: S608 - `column` allowlisted above
            f"FROM findings GROUP BY {column}"
        )
        rows = conn.execute(text(sql))
        return {row[0]: row[1] for row in rows}
