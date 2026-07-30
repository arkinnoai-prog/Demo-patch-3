"""Environment-driven configuration.

Everything the worker needs comes from the environment so the same image runs as a
Container Apps Job, as a long-lived Container App, and on a laptop with no cloud
credentials at all.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from app import __version__

VALID_ENVIRONMENTS = ("test", "staging", "production", "local")

# The database is PostgreSQL in every environment.  This default matches the dev server
# in docker-compose.yml (host `localhost` rather than the compose service name `postgres`),
# so `python -m app.cli run` works against `docker compose up postgres` with no DATABASE_URL
# set.  In Azure, DATABASE_URL points at the shared PostgreSQL Flexible Server.
DEFAULT_DATABASE_URL = "postgresql+psycopg2://baobao:localdev@localhost:5432/baobao"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    """Resolved runtime configuration."""

    environment: str = "local"
    version: str = __version__
    image_tag: str = "dev"

    # Persistence.  PostgreSQL everywhere — locally the dev server from docker-compose
    # (`docker compose up postgres`), in Azure the SHARED PostgreSQL Flexible Server, the
    # same server baobao-payments-api uses, which is what gives the impact-analysis screen
    # a genuine blast radius (POC-PLAN.md §1).  There is no SQLite fallback: the worker
    # talks to the same engine on a laptop as it does in the estate.
    database_url: str = DEFAULT_DATABASE_URL

    # Ba0Ba0 control plane sink.
    baobao_endpoint: str = ""
    baobao_timeout: int = 15
    baobao_batch_size: int = 50
    baobao_max_retries: int = 3

    manifest_path: Path = field(default_factory=lambda: Path("samples/job-manifest.yaml"))
    data_dir: Path = field(default_factory=lambda: Path("data"))
    log_level: str = "INFO"
    dry_run: bool = False

    @classmethod
    def from_env(cls) -> Config:
        environment = _env("APP_ENV", "local").lower()
        if environment not in VALID_ENVIRONMENTS:
            environment = "local"

        data_dir = Path(_env("WORKER_DATA_DIR", "data"))
        database_url = _env("DATABASE_URL") or DEFAULT_DATABASE_URL

        return cls(
            environment=environment,
            image_tag=_env("IMAGE_TAG", "dev"),
            database_url=database_url,
            baobao_endpoint=_env("BAOBAO_INGEST_URL"),
            baobao_timeout=_env_int("BAOBAO_TIMEOUT_SECONDS", 15),
            baobao_batch_size=_env_int("BAOBAO_BATCH_SIZE", 50),
            baobao_max_retries=_env_int("BAOBAO_MAX_RETRIES", 3),
            manifest_path=Path(_env("JOB_MANIFEST", "samples/job-manifest.yaml")),
            data_dir=data_dir,
            log_level=_env("LOG_LEVEL", "INFO").upper(),
            dry_run=_env_bool("DRY_RUN", False),
        )

    @property
    def reporting_enabled(self) -> bool:
        """False when no control plane is configured — the job still runs and persists."""
        return bool(self.baobao_endpoint) and not self.dry_run
