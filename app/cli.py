"""Container entrypoint.

    python -m app.cli run    --manifest samples/job-manifest.yaml   # Container Apps Job
    python -m app.cli serve  --port 8080                            # Container App
    python -m app.cli check                                         # config/db preflight

Exit codes matter here — an Azure Container Apps Job is judged by them, and `deploy.yml`
gates promotion on the job succeeding:

    0  run completed
    1  run failed (bad manifest, unreadable source with fail_on_source_error, DB down)
    2  run completed but a source or the control-plane report failed (partial success)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from app import __version__, db
from app.config import Config
from app.jobs.runner import run_job, summary_text
from app.manifest import ManifestError, load_manifest

log = logging.getLogger("app.cli")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_PARTIAL = 2


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
        stream=sys.stdout,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="app.cli", description="baobao-batch-worker — scanner report ingestion"
    )
    parser.add_argument("--version", action="version", version=f"baobao-batch-worker {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="execute one ingestion run and exit")
    run.add_argument("--manifest", type=Path, default=None, help="path to the job manifest")
    run.add_argument("--dry-run", action="store_true", help="skip the control-plane report")
    run.add_argument("--json", action="store_true", help="emit the summary as JSON")

    serve = sub.add_parser("serve", help="run the HTTP API (development server)")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=8080)

    sub.add_parser("check", help="validate config, manifest and database connectivity")
    return parser


def _config_for(args: argparse.Namespace) -> Config:
    config = Config.from_env()
    overrides = {}
    if getattr(args, "manifest", None):
        overrides["manifest_path"] = Path(args.manifest)
    if getattr(args, "dry_run", False):
        overrides["dry_run"] = True
    if overrides:
        config = Config(**{**config.__dict__, **overrides})
    return config


def cmd_run(args: argparse.Namespace) -> int:
    config = _config_for(args)
    engine = db.create_db_engine(config.database_url)
    db.init_schema(engine)

    try:
        manifest = load_manifest(config.manifest_path)
    except ManifestError as exc:
        log.error("manifest error — %s", exc)
        return EXIT_FAILED

    try:
        summary = run_job(engine, config, manifest)
    except Exception as exc:  # noqa: BLE001 - the exit code is the contract
        log.error("run failed — %s", exc)
        return EXIT_FAILED

    if args.json:
        import json

        payload = summary.to_dict()
        payload.pop("findings", None)
        print(json.dumps(payload, indent=2))
    else:
        print(summary_text(summary))

    return EXIT_PARTIAL if summary.source_errors else EXIT_OK


def cmd_serve(args: argparse.Namespace) -> int:
    from app.main import create_app

    config = _config_for(args)
    log.warning("development server — production uses gunicorn (see Dockerfile CMD)")
    # ⚠️  SEEDED VULNERABILITY — Flask debug mode (CWE-489).  `debug=True` exposes the
    # Werkzeug interactive debugger (arbitrary code execution via the console) and leaks
    # tracebacks.  Bandit flags this as B201, CodeQL as py/flask-debug.
    create_app(config).run(host=args.host, port=args.port, debug=True)  # noqa: S201
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    config = _config_for(args)
    ok = True

    print(f"version      {__version__}")
    print(f"environment  {config.environment}")
    print(f"database     {db._redact_url(config.database_url)}")
    print(f"manifest     {config.manifest_path}")
    print(f"sink         {config.baobao_endpoint or '(none — local persistence only)'}")

    try:
        manifest = load_manifest(config.manifest_path)
        print(f"manifest ok  {manifest.name}: {manifest.source_count} source(s)")
    except ManifestError as exc:
        print(f"manifest ERR {exc}")
        ok = False

    engine = db.create_db_engine(config.database_url)
    try:
        db.init_schema(engine)
        print(f"database ok  reachable={db.ping(engine)}")
    except Exception as exc:  # noqa: BLE001
        print(f"database ERR {exc}")
        ok = False

    return EXIT_OK if ok else EXIT_FAILED


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _configure_logging(Config.from_env().log_level)

    handlers = {"run": cmd_run, "serve": cmd_serve, "check": cmd_check}
    return handlers[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
