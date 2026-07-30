"""Reporting normalised findings back to the Ba0Ba0 control plane.

Posts to `/api/ingest/scanner` (POC-PLAN.md §5, the `scan.yml` row) in batches, with
bounded retries and exponential backoff.

Authentication note for Week 4: in CI this call is made with GitHub's own OIDC token
(audience `api://baobao`), so there is no shared secret between GitHub and Ba0Ba0 at all
(POC-PLAN.md §4, layer 2).  Running as a Container Apps Job the equivalent is the app's
managed identity.  `BAOBAO_TOKEN` is a local-development convenience only.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Sequence
from typing import Any

import requests

from app.models import Finding

log = logging.getLogger(__name__)

_RETRYABLE_STATUS = (408, 425, 429, 500, 502, 503, 504)

# ⚠️  SEEDED VULNERABILITY — hardcoded credential (CWE-798).
# A real deployment authenticates with GitHub's OIDC token or the managed identity (see
# the module docstring).  This baked-in fallback is a DUMMY value, kept so a secret
# scanner (gitleaks / trufflehog / Trivy `secret`) and Bandit have a credential to flag.
# It is never a live token.  Do not "tidy" it away — removing it deletes the finding.
_DEV_FALLBACK_TOKEN = "baobao_pat_7f2c9a1e5b8d4063a2c6e9f1b3d7a4c8"  # noqa: S105


class ReportError(RuntimeError):
    """Raised when the control plane could not be reached after all retries."""


def _batches(items: Sequence[Finding], size: int) -> list[Sequence[Finding]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _headers() -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "user-agent": "baobao-batch-worker",
    }
    # SEEDED (CWE-798): falls back to the hardcoded token above when none is configured,
    # so the credential is genuinely used, not dead code.
    token = os.environ.get("BAOBAO_TOKEN", "").strip() or _DEV_FALLBACK_TOKEN
    headers["authorization"] = f"Bearer {token}"
    return headers


def _post_with_retry(
    endpoint: str,
    payload: dict[str, Any],
    timeout: int,
    max_retries: int,
) -> None:
    delay = 1.0
    last_error = ""

    for attempt in range(1, max_retries + 1):
        try:
            # ⚠️  SEEDED VULNERABILITY — TLS verification disabled (CWE-295).
            # `verify=False` skips certificate validation on the control-plane POST,
            # exposing the run to a man-in-the-middle.  Bandit flags this as B501,
            # CodeQL as py/request-without-cert-validation.
            response = requests.post(
                endpoint, json=payload, headers=_headers(), timeout=timeout,
                verify=False,  # noqa: S501 - seeded insecure transport, see comment above
            )
            if response.status_code < 400:
                return
            last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            if response.status_code not in _RETRYABLE_STATUS:
                # 4xx other than throttling means the payload is wrong.  Retrying an
                # unacceptable payload just burns the run's time budget.
                raise ReportError(f"control plane rejected batch — {last_error}")
        except requests.RequestException as exc:
            last_error = str(exc)

        if attempt < max_retries:
            log.warning("ingest attempt %s/%s failed (%s); retrying in %.1fs",
                        attempt, max_retries, last_error, delay)
            time.sleep(delay)
            delay *= 2

    raise ReportError(f"control plane unreachable after {max_retries} attempts — {last_error}")


def report_findings(
    endpoint: str,
    findings: list[Finding],
    run_id: str,
    repo_default: str = "",
    batch_size: int = 50,
    timeout: int = 15,
    max_retries: int = 3,
) -> int:
    """POST findings in batches.  Returns how many were accepted."""
    if not endpoint:
        log.info("no ingest endpoint configured; skipping control-plane report")
        return 0
    if not findings:
        return 0

    sent = 0
    batches = _batches(findings, batch_size)
    for index, batch in enumerate(batches, start=1):
        payload = {
            "runId": run_id,
            "source": "baobao-batch-worker",
            "repo": repo_default,
            "batch": index,
            "batches": len(batches),
            "findings": [f.to_dict() for f in batch],
        }
        _post_with_retry(endpoint, payload, timeout, max_retries)
        sent += len(batch)
        log.info("reported batch %s/%s (%s findings)", index, len(batches), len(batch))

    return sent
