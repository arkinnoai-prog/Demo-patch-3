"""Batch run orchestration.

    manifest → fetch → parse → enrich → dedupe → persist → report

One run, one `job_runs` row, one summary.  A source that fails is recorded and skipped
rather than aborting the run: a single unreachable scanner artifact should not lose the
other four repos' findings.  `fail_on_source_error: true` in the manifest flips that for
runs where partial data is worse than none.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any

import requests
from sqlalchemy.engine import Engine

from app import db, parsers
from app.config import Config
from app.jobs.archive import ArchiveError, read_member
from app.jobs.report import ReportError, report_findings
from app.manifest import Manifest, Source, load_manifest
from app.models import Finding, RunSummary, utcnow
from app.normalise import dedupe, enrich, summarise

log = logging.getLogger(__name__)


class SourceError(RuntimeError):
    """A single source could not be read or parsed."""


def _load_document(source: Source, config: Config, work_dir: Path) -> Any:
    """Resolve a source to a parsed JSON document."""
    if source.archive:
        bundle = Path(source.archive)
        member = source.member or "report.json"
        try:
            extracted = read_member(bundle, member, work_dir / source.id)
        except ArchiveError as exc:
            raise SourceError(str(exc)) from exc
        return json.loads(extracted.read_text(encoding="utf-8"))

    if source.url:
        try:
            response = requests.get(source.url, timeout=config.baobao_timeout)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            raise SourceError(f"could not fetch {source.url}: {exc}") from exc

    path = Path(source.path)
    if not path.is_file():
        raise SourceError(f"report not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SourceError(f"invalid JSON in {path}: {exc}") from exc


def collect(manifest: Manifest, config: Config) -> tuple:
    """Read every source and return (findings, errors).

    Returns raw findings — enrichment and dedupe happen once, over the whole set, so
    the same CVE seen by two scanners collapses to one row.
    """
    findings: list[Finding] = []
    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="baobao-ingest-") as tmp:
        work_dir = Path(tmp)
        for source in manifest.sources:
            try:
                document = _load_document(source, config, work_dir)
                parsed = parsers.parse(source.kind, document, source.repo)
            except (SourceError, parsers.UnknownScannerError, OSError) as exc:
                message = f"{source.id}: {exc}"
                log.error("source failed — %s", message)
                errors.append(message)
                if manifest.fail_on_source_error:
                    raise SourceError(message) from exc
                continue

            log.info("source %s (%s/%s): %s raw findings",
                     source.id, source.repo, source.kind, len(parsed))
            findings.extend(parsed)

    return findings, errors


def run_job(
    engine: Engine,
    config: Config,
    manifest: Manifest | None = None,
) -> RunSummary:
    """Execute one ingestion run end to end."""
    manifest = manifest or load_manifest(config.manifest_path)
    endpoint = config.baobao_endpoint or manifest.sink_endpoint

    run = db.start_run(engine, manifest.name, config.environment)
    run.sources = manifest.source_count
    log.info("run %s started — manifest %r, %s source(s)", run.id, manifest.name, run.sources)

    summary = RunSummary(run=run)

    try:
        raw, errors = collect(manifest, config)
        summary.source_errors = errors

        findings = dedupe(enrich(raw))
        by_severity, by_channel, ratio = summarise(findings)

        run.findings_new = db.upsert_findings(engine, findings, run.id)
        run.findings_ingested = len(findings)
        run.mechanical_ratio = ratio

        summary.findings = findings
        summary.by_severity = by_severity
        summary.by_channel = by_channel

        if endpoint and config.reporting_enabled:
            try:
                summary.reported = report_findings(
                    endpoint,
                    findings,
                    run_id=run.id,
                    batch_size=manifest.batch_size or config.baobao_batch_size,
                    timeout=config.baobao_timeout,
                    max_retries=config.baobao_max_retries,
                )
            except ReportError as exc:
                # Findings are already persisted locally; the control plane can
                # re-pull.  Losing the run over a transient sink outage would be worse.
                log.error("control-plane report failed — %s", exc)
                summary.source_errors.append(f"report: {exc}")

        run.status = "succeeded"
        log.info(
            "run %s succeeded — %s findings (%s new), %.0f%% mechanically routable",
            run.id, run.findings_ingested, run.findings_new, ratio * 100,
        )
    except Exception as exc:  # noqa: BLE001 - the run row must record any failure
        run.status = "failed"
        run.error = str(exc)[:1000]
        log.exception("run %s failed", run.id)
        raise
    finally:
        run.finished_at = utcnow()
        db.finish_run(engine, run)

    return summary


def summary_text(summary: RunSummary) -> str:
    """Human-readable run report for job logs and the CLI."""
    run = summary.run
    lines = [
        f"run          {run.id}",
        f"manifest     {run.name}",
        f"environment  {run.environment}",
        f"status       {run.status}",
        f"sources      {run.sources}",
        f"findings     {run.findings_ingested} ({run.findings_new} new)",
        f"mechanical   {run.mechanical_ratio * 100:.0f}% routable without an LLM",
        f"reported     {summary.reported} to control plane",
    ]

    severities = {k: v for k, v in summary.by_severity.items() if v}
    if severities:
        lines.append("severity     " + "  ".join(f"{k}={v}" for k, v in severities.items()))
    if summary.by_channel:
        lines.append("channels     " + "  ".join(f"{k}={v}" for k, v in summary.by_channel.items()))
    for error in summary.source_errors:
        lines.append(f"WARN         {error}")

    return "\n".join(lines)


def metrics(engine: Engine) -> dict[str, Any]:
    """Aggregates behind `GET /metrics`."""
    return {
        "by_severity": db.counts_by(engine, "severity"),
        "by_channel": db.counts_by(engine, "remediation_channel"),
        "by_repo": db.counts_by(engine, "repo"),
        "by_scanner": db.counts_by(engine, "source_scanner"),
    }
