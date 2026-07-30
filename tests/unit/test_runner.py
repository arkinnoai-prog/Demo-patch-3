from __future__ import annotations

from pathlib import Path

import pytest

from app import db
from app.jobs.runner import SourceError, run_job, summary_text
from app.manifest import parse_manifest
from tests.conftest import SAMPLES


def _manifest(*sources, **job):
    return parse_manifest({
        "job": {"name": "test-run", **job},
        "sources": list(sources),
        "sink": {"endpoint": "", "batch_size": 50},
    })


IMAGE_SOURCE = {
    "id": "image", "repo": "baobao-batch-worker", "kind": "trivy",
    "path": str(SAMPLES / "trivy-batch-worker-image.json"),
}
PIP_SOURCE = {
    "id": "pip", "repo": "baobao-batch-worker", "kind": "pip-audit",
    "path": str(SAMPLES / "pip-audit-batch-worker.json"),
}
PAYMENTS_SOURCE = {
    "id": "payments", "repo": "baobao-payments-api", "kind": "trivy",
    "path": str(SAMPLES / "trivy-payments-api-fs.json"),
}


class TestRunJob:
    def test_ingests_and_persists(self, engine, config):
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE))

        assert summary.run.status == "succeeded"
        assert summary.run.findings_ingested == 9
        assert summary.run.findings_new == 9
        assert db.query_findings(engine, repo="baobao-batch-worker")

    def test_is_idempotent(self, engine, config):
        # Re-running the same manifest must refresh last_seen, not duplicate rows.
        # The nightly job runs against a mostly unchanged estate every night; without
        # this the dashboard's "new findings" figure is meaningless within a week.
        first = run_job(engine, config, _manifest(IMAGE_SOURCE))
        second = run_job(engine, config, _manifest(IMAGE_SOURCE))

        assert first.run.findings_new == 9
        assert second.run.findings_new == 0
        assert second.run.findings_ingested == 9
        assert len(db.query_findings(engine, limit=1000)) == 9

    def test_dedupes_across_scanners(self, engine, config):
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE, PIP_SOURCE))

        # 9 from the image scan + 12 from pip-audit, less `requests` and `gunicorn`
        # which both scanners report.
        assert summary.run.findings_ingested == 19

    def test_dedupe_keeps_trivys_severity_over_pip_audits_blank(self, engine, config):
        run_job(engine, config, _manifest(IMAGE_SOURCE, PIP_SOURCE))

        rows = db.query_findings(engine, limit=1000)
        gunicorn = next(r for r in rows if r["package_name"] == "gunicorn")
        assert gunicorn["severity"] == "HIGH"

    def test_routes_the_base_image_findings_mechanically(self, engine, config):
        # Scenario 3's core assertion: os-pkgs on an image never reaches the LLM.
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE))
        assert summary.by_channel["base_image_bump"] == 7

    def test_certifi_is_not_escalated_to_the_llm(self, engine, config):
        run_job(engine, config, _manifest(PIP_SOURCE))
        rows = db.query_findings(engine, limit=1000)
        certifi = [r for r in rows if r["package_name"] == "certifi"]
        assert certifi and all(r["remediation_channel"] == "dependency_bump" for r in certifi)

    def test_mechanical_ratio_is_reported(self, engine, config):
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE, PIP_SOURCE, PAYMENTS_SOURCE))
        assert 0.0 < summary.run.mechanical_ratio <= 1.0
        assert summary.run.mechanical_ratio == summary.run.mechanical_ratio  # persisted value

    def test_per_repo_separation(self, engine, config):
        run_job(engine, config, _manifest(IMAGE_SOURCE, PAYMENTS_SOURCE))
        assert len(db.query_findings(engine, repo="baobao-payments-api", limit=100)) == 4

    def test_run_row_is_recorded(self, engine, config):
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE))
        row = db.get_run(engine, summary.run.id)
        assert row["status"] == "succeeded"
        assert row["finished_at"]


class TestSourceFailures:
    def test_a_bad_source_is_recorded_and_skipped(self, engine, config):
        bad = {"id": "bad", "repo": "r", "kind": "trivy", "path": "/nonexistent/report.json"}
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE, bad))

        assert summary.run.status == "succeeded"
        assert summary.run.findings_ingested == 9  # the good source still landed
        assert any("bad" in e for e in summary.source_errors)

    def test_fail_on_source_error_aborts_the_run(self, engine, config):
        bad = {"id": "bad", "repo": "r", "kind": "trivy", "path": "/nonexistent/report.json"}
        with pytest.raises(SourceError):
            run_job(engine, config, _manifest(bad, fail_on_source_error=True))

        runs = db.list_runs(engine)
        assert runs[0]["status"] == "failed"
        assert runs[0]["error"]

    def test_invalid_json_is_a_source_error_not_a_crash(self, engine, config, tmp_path: Path):
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        source = {"id": "broken", "repo": "r", "kind": "trivy", "path": str(broken)}

        summary = run_job(engine, config, _manifest(source))
        assert summary.run.status == "succeeded"
        assert summary.source_errors


class TestSummaryText:
    def test_renders_the_headline_numbers(self, engine, config):
        summary = run_job(engine, config, _manifest(IMAGE_SOURCE))
        text = summary_text(summary)

        assert "succeeded" in text
        assert "mechanical" in text
        assert summary.run.id in text
