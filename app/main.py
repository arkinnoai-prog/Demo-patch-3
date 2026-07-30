"""Flask application.

The same image runs two ways (POC-PLAN.md §1 — Container Apps job):

  * as a long-lived Container App — this API, providing the health/readiness surface the
    revision-based deploy and the post-deploy smoke test need;
  * as a scheduled Container Apps Job — `app.cli run`, no HTTP at all.

No authentication, deliberately: this service sits inside the estate's network boundary
and is driven by Container Apps Jobs and smoke tests.  Auth belongs in the Ba0Ba0 control
plane, not in a patch target (IMPLEMENTATION-PLAN.md §9).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, send_file

from app import __version__, db
from app.config import Config
from app.jobs.runner import metrics, run_job
from app.manifest import ManifestError, load_manifest, parse_manifest
from app.models import utcnow

log = logging.getLogger(__name__)

# The built React SPA (Vite output).  Locally: `cd frontend && npm run build`.  In the
# container the Node build stage writes it here too (see Dockerfile), so one image serves
# the API and the UI on the same port — no separate frontend service to deploy.
WEBUI_DIR = Path(os.environ.get("WEBUI_DIR", "frontend/dist")).resolve()


def create_app(config: Config | None = None) -> Flask:
    config = config or Config.from_env()
    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    )

    app = Flask(__name__, static_folder=str(WEBUI_DIR / "assets"), static_url_path="/assets")
    app.config["BAOBAO"] = config

    engine = db.create_db_engine(config.database_url)
    db.init_schema(engine)
    app.config["ENGINE"] = engine

    # --- frontend ----------------------------------------------------------

    @app.get("/")
    def index() -> Any:
        """Serve the React app.  Falls back to a JSON pointer when the UI has not been
        built, so the API and the health probes work with or without a frontend build."""
        index_html = WEBUI_DIR / "index.html"
        if index_html.is_file():
            return send_file(index_html)
        return jsonify(
            service="baobao-batch-worker",
            message="frontend not built — run `cd frontend && npm install && npm run build`",
            api=["/api/findings", "/api/jobs", "/metrics", "/healthz", "/readyz"],
        )

    # --- liveness / readiness ---------------------------------------------

    @app.get("/healthz")
    def healthz() -> Any:
        """Liveness.  Deliberately does NOT touch the database — a Postgres blip
        should not make Container Apps kill an otherwise healthy revision."""
        return jsonify(
            status="ok",
            service="baobao-batch-worker",
            version=__version__,
            image_tag=config.image_tag,
            environment=config.environment,
            time=utcnow(),
        )

    @app.get("/readyz")
    def readyz() -> Any:
        """Readiness.  This one does check the database, because a worker that cannot
        reach Postgres cannot do its job."""
        ok = db.ping(engine)
        payload = {"status": "ready" if ok else "degraded", "database": ok, "time": utcnow()}
        return jsonify(payload), (200 if ok else 503)

    @app.get("/metrics")
    def metrics_route() -> Any:
        return jsonify(metrics(engine))

    # --- jobs ---------------------------------------------------------------

    @app.post("/api/jobs/run")
    def trigger_run() -> Any:
        """Run the ingestion job synchronously.

        Body (all optional):
            {"manifest": "<path>"}          — load a manifest from disk, or
            {"manifest": {...}}             — an inline manifest document
        """
        body: dict[str, Any] = request.get_json(silent=True) or {}
        raw_manifest = body.get("manifest")

        try:
            if isinstance(raw_manifest, dict):
                manifest = parse_manifest(raw_manifest)
            elif isinstance(raw_manifest, str) and raw_manifest:
                manifest = load_manifest(raw_manifest)
            else:
                manifest = load_manifest(config.manifest_path)
        except ManifestError as exc:
            return jsonify(error="invalid manifest", detail=str(exc)), 400

        try:
            summary = run_job(engine, config, manifest)
        except Exception as exc:  # noqa: BLE001 - surface the failure, keep serving
            log.exception("job run failed")
            return jsonify(error="job failed", detail=str(exc)), 500

        payload = summary.to_dict()
        payload.pop("findings", None)  # keep the response small; use /api/findings
        return jsonify(payload), 200

    @app.get("/api/jobs")
    def list_jobs() -> Any:
        return jsonify(runs=db.list_runs(engine, limit=_int_arg("limit", 20, 200)))

    @app.get("/api/jobs/<run_id>")
    def get_job(run_id: str) -> Any:
        run = db.get_run(engine, run_id)
        if run is None:
            return jsonify(error="not found", run_id=run_id), 404
        return jsonify(run)

    # --- findings -----------------------------------------------------------

    @app.get("/api/findings")
    def list_findings() -> Any:
        limit = _int_arg("limit", 200, 1000)
        search = request.args.get("search", "").strip()
        if search:
            # Free-text search — routes through the seeded SQL-injection sink
            # (db.search_findings, CWE-89).  The filtered listing below stays safe.
            rows = db.search_findings(engine, search, limit=limit)
        else:
            rows = db.query_findings(
                engine,
                repo=request.args.get("repo", "").strip(),
                severity=request.args.get("severity", "").strip(),
                channel=request.args.get("channel", "").strip(),
                limit=limit,
            )
        return jsonify(count=len(rows), findings=rows)

    @app.errorhandler(404)
    def not_found(_: Any) -> Any:
        return jsonify(error="not found", path=request.path), 404

    return app


def _int_arg(name: str, default: int, maximum: int) -> int:
    raw = request.args.get(name, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


# Convenience for `flask run` and for gunicorn's `app.main:create_app()` factory syntax.
if __name__ == "__main__":  # pragma: no cover
    create_app().run(host="0.0.0.0", port=8080)
