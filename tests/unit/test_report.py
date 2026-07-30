"""Control-plane reporting: batching, retries, and what is *not* retried.

`requests.post` is stubbed by hand rather than with `responses`, which needs
requests ≥2.30 and so cannot be installed next to the seeded requests==2.25.1 pin.
See requirements-dev.txt.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import requests

from app.jobs.report import ReportError, report_findings
from app.normalise import enrich

ENDPOINT = "https://baobao.example/api/ingest/scanner"


class FakeResponse:
    def __init__(self, status_code: int, text: str = "{}"):
        self.status_code = status_code
        self.text = text


class PostRecorder:
    """Stands in for `requests.post`, replaying a scripted sequence of outcomes.

    An outcome is either an int status code or an exception instance to raise.  The
    last outcome repeats once the script runs out, so a test can say "always 503"
    with a single entry.
    """

    def __init__(self, outcomes: list[Any]):
        self.outcomes = outcomes
        self.calls: list[dict[str, Any]] = []

    def __call__(self, url: str, json=None, headers=None, timeout=None, verify=None):
        self.calls.append({"url": url, "json": json, "headers": headers or {},
                           "timeout": timeout, "verify": verify})
        outcome = self.outcomes[min(len(self.calls) - 1, len(self.outcomes) - 1)]
        if isinstance(outcome, Exception):
            raise outcome
        return FakeResponse(outcome)

    @property
    def count(self) -> int:
        return len(self.calls)


@pytest.fixture
def findings(make_finding):
    return enrich([
        make_finding(vuln_id=f"CVE-2024-{i:04d}", package_name=f"pkg{i}") for i in range(5)
    ])


@pytest.fixture
def post(monkeypatch):
    """Install a PostRecorder and disable backoff sleeps."""
    monkeypatch.setattr("app.jobs.report.time.sleep", lambda _: None)

    def _install(*outcomes) -> PostRecorder:
        recorder = PostRecorder(list(outcomes) or [202])
        monkeypatch.setattr(requests, "post", recorder)
        return recorder

    return _install


class TestReportFindings:
    def test_posts_every_finding(self, findings, post):
        recorder = post(202)
        assert report_findings(ENDPOINT, findings, run_id="r1") == 5
        assert recorder.count == 1

    def test_batches(self, findings, post):
        recorder = post(202)
        assert report_findings(ENDPOINT, findings, run_id="r1", batch_size=2) == 5
        assert recorder.count == 3  # 2 + 2 + 1

    def test_batch_metadata_is_included(self, findings, post):
        recorder = post(202)
        report_findings(ENDPOINT, findings, run_id="run-42", batch_size=2)

        payload = recorder.calls[0]["json"]
        assert payload["runId"] == "run-42"
        assert payload["source"] == "baobao-batch-worker"
        assert (payload["batch"], payload["batches"]) == (1, 3)
        assert len(payload["findings"]) == 2

    def test_payload_is_json_serialisable(self, findings, post):
        # The findings carry dataclass-derived dicts; if a field ever stops being a
        # primitive, requests would fail at send time inside a nightly job.
        recorder = post(202)
        report_findings(ENDPOINT, findings, run_id="r1")
        json.dumps(recorder.calls[0]["json"])

    def test_no_endpoint_is_a_no_op(self, findings, post):
        recorder = post(202)
        assert report_findings("", findings, run_id="r1") == 0
        assert recorder.count == 0

    def test_no_findings_is_a_no_op(self, post):
        recorder = post(202)
        assert report_findings(ENDPOINT, [], run_id="r1") == 0
        assert recorder.count == 0


class TestRetries:
    def test_retries_a_503_then_succeeds(self, findings, post):
        recorder = post(503, 202)
        assert report_findings(ENDPOINT, findings, run_id="r1", max_retries=3) == 5
        assert recorder.count == 2

    def test_retries_a_429(self, findings, post):
        recorder = post(429, 202)
        assert report_findings(ENDPOINT, findings, run_id="r1", max_retries=3) == 5
        assert recorder.count == 2

    def test_retries_a_connection_error(self, findings, post):
        recorder = post(requests.ConnectionError("connection refused"), 202)
        assert report_findings(ENDPOINT, findings, run_id="r1", max_retries=3) == 5
        assert recorder.count == 2

    def test_gives_up_after_max_retries(self, findings, post):
        recorder = post(503)
        with pytest.raises(ReportError, match="unreachable after 2 attempts"):
            report_findings(ENDPOINT, findings, run_id="r1", max_retries=2)
        assert recorder.count == 2

    def test_does_not_retry_a_400(self, findings, post):
        # A rejected payload will be rejected identically next time; retrying it only
        # burns the job's time budget and delays the rest of the estate's ingestion.
        recorder = post(400)
        with pytest.raises(ReportError, match="rejected batch"):
            report_findings(ENDPOINT, findings, run_id="r1", max_retries=3)
        assert recorder.count == 1

    def test_does_not_retry_a_401(self, findings, post):
        recorder = post(401)
        with pytest.raises(ReportError, match="rejected batch"):
            report_findings(ENDPOINT, findings, run_id="r1", max_retries=3)
        assert recorder.count == 1


class TestAuth:
    def test_bearer_token_is_sent_when_present(self, findings, post, monkeypatch):
        monkeypatch.setenv("BAOBAO_TOKEN", "tok-123")
        recorder = post(202)
        report_findings(ENDPOINT, findings, run_id="r1")

        assert recorder.calls[0]["headers"]["authorization"] == "Bearer tok-123"

    def test_falls_back_to_the_hardcoded_dev_token(self, findings, post, monkeypatch):
        # SEEDED (CWE-798): with no BAOBAO_TOKEN set, the client falls back to a token
        # hardcoded in app/jobs/report.py.  This documents that the seeded credential is
        # really used — it is the value a secret scanner and Bandit flag.
        monkeypatch.delenv("BAOBAO_TOKEN", raising=False)
        recorder = post(202)
        report_findings(ENDPOINT, findings, run_id="r1")

        assert recorder.calls[0]["headers"]["authorization"].startswith("Bearer baobao_pat_")

    def test_tls_verification_is_disabled(self, findings, post):
        # SEEDED (CWE-295): the control-plane POST sets verify=False.
        recorder = post(202)
        report_findings(ENDPOINT, findings, run_id="r1")

        assert recorder.calls[0]["verify"] is False

    def test_timeout_is_passed_through(self, findings, post):
        # A nightly job with no timeout can hang until the Container Apps Job's own
        # limit kills it, losing the run summary entirely.
        recorder = post(202)
        report_findings(ENDPOINT, findings, run_id="r1", timeout=7)
        assert recorder.calls[0]["timeout"] == 7
