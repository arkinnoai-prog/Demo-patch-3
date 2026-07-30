from __future__ import annotations

import json
import os
import tarfile
import urllib.parse
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError

from app import db
from app.config import DEFAULT_DATABASE_URL, Config
from app.models import Finding

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "samples"

# The suite runs against PostgreSQL — the same engine the worker uses everywhere else,
# so tests exercise the real dialect (ON CONFLICT, bind-parameter chunking) rather than a
# SQLite stand-in.  Point it at any Postgres with `TEST_DATABASE_URL`; the default is the
# docker-compose dev server (`docker compose up postgres`).
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", DEFAULT_DATABASE_URL)


@pytest.fixture(scope="session")
def _pg_admin() -> Iterator[Engine]:
    """A session-lived engine on the base database, used only to create and drop the
    per-test schemas.  Fails loudly with actionable guidance if no Postgres is reachable —
    an unreachable database should not look like a mysterious fixture error."""
    admin = create_engine(TEST_DATABASE_URL, future=True, pool_pre_ping=True)
    try:
        with admin.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError as exc:  # pragma: no cover - environment guard
        admin.dispose()
        pytest.fail(
            "cannot reach PostgreSQL for the test suite at "
            f"{db._redact_url(TEST_DATABASE_URL)}.\n"
            "Start one with `docker compose up -d postgres`, or set TEST_DATABASE_URL.\n"
            f"({type(exc).__name__}: {exc})",
            pytrace=False,
        )
    yield admin
    admin.dispose()


@pytest.fixture
def config(_pg_admin: Engine, tmp_path: Path) -> Iterator[Config]:
    """Config bound to a throwaway Postgres schema and no control plane.

    Each test gets its own schema (`t_<uuid>`), created here and dropped on teardown, so
    tests are isolated and order-independent on one shared database.  The schema is pinned
    via the libpq `options` connection parameter, so every engine built from this
    `database_url` — the test's own and the Flask app's — lands in the same namespace.
    """
    schema = f"t_{uuid.uuid4().hex}"
    with _pg_admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))

    search_path = urllib.parse.quote(f"-csearch_path={schema}")
    database_url = f"{TEST_DATABASE_URL}?options={search_path}"

    yield Config(
        environment="test",
        database_url=database_url,
        baobao_endpoint="",
        manifest_path=SAMPLES / "job-manifest.yaml",
        data_dir=tmp_path,
        log_level="WARNING",
    )

    with _pg_admin.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


@pytest.fixture
def engine(config: Config) -> Iterator[Engine]:
    eng = db.create_db_engine(config.database_url)
    db.init_schema(eng)
    yield eng
    eng.dispose()  # release pooled connections before the schema is dropped


@pytest.fixture
def client(config: Config):
    from app.main import create_app

    app = create_app(config)
    app.config["TESTING"] = True
    try:
        with app.test_client() as test_client:
            yield test_client
    finally:
        app.config["ENGINE"].dispose()  # same: don't hold connections into teardown


@pytest.fixture
def sample():
    def _load(name: str):
        return json.loads((SAMPLES / name).read_text(encoding="utf-8"))

    return _load


@pytest.fixture
def make_finding() -> Callable[..., Finding]:
    def _make(**overrides) -> Finding:
        defaults = dict(
            repo="baobao-batch-worker",
            source_scanner="trivy",
            vuln_id="CVE-2023-00000",
            severity="HIGH",
            package_name="somepkg",
            installed_version="1.0.0",
            fixed_version="1.0.1",
            target="requirements.txt",
            target_class="lang-pkgs",
            artifact_type="repository",
        )
        defaults.update(overrides)
        return Finding(**defaults)

    return _make


@pytest.fixture
def make_tar(tmp_path: Path):
    """Build a tar containing (arcname, content) pairs.

    Written with a raw TarInfo rather than `tarfile.add` so a member name can carry
    `../` or a leading `/` — which is exactly what the traversal tests need and what
    `tarfile.add` would normalise away.
    """

    def _make(name: str, members) -> Path:
        bundle = tmp_path / name
        with tarfile.open(bundle, "w:gz") as archive:
            for arcname, content in members:
                data = content.encode() if isinstance(content, str) else content
                info = tarfile.TarInfo(name=arcname)
                info.size = len(data)
                info.mode = 0o644
                import io

                archive.addfile(info, io.BytesIO(data))
        return bundle

    return _make
