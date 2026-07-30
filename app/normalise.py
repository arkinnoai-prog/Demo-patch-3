"""Severity normalisation, fingerprinting, dedupe, and the remediation router.

The router is the plain-code half of POC-PLAN.md §7: a deterministic strategy router
sits in front of the LLM, and roughly 60% of findings never reach it.  Nothing in this
module calls a model — that is the point, and `mechanical_ratio` in the run summary is
the live evidence for it.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from app.models import SEVERITY_ORDER, Finding

_SEVERITY_ALIASES = {
    "CRITICAL": "CRITICAL",
    "IMPORTANT": "HIGH",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "NEGLIGIBLE": "LOW",
    "INFO": "LOW",
    "INFORMATIONAL": "LOW",
    "UNKNOWN": "UNKNOWN",
    "": "UNKNOWN",
}

# Scanners that produce code findings rather than package findings.
_SAST_SCANNERS = {"codeql", "bandit", "semgrep"}
_IAC_SCANNERS = {"checkov", "tfsec", "terrascan"}

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def normalise_severity(raw: str) -> str:
    """Map a scanner's severity vocabulary onto ours."""
    key = (raw or "").strip().upper()
    return _SEVERITY_ALIASES.get(key, "UNKNOWN")


def severity_from_cvss(score: float) -> str:
    """CVSS v3 qualitative rating.  Used when a scanner omits a severity string."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def fingerprint(finding: Finding) -> str:
    """Stable identity for a finding: *this package, in this repo, has this CVE*.

    Deliberately excludes three things:

    * **versions and timestamps** — bumping a package from one vulnerable version to
      another vulnerable version is the same finding with a new `last_seen`, not a new
      row;
    * **the scanner** — Trivy fs and pip-audit both report Flask's CVE-2023-30861, and
      the CAB should see one finding, not two;
    * **the target path** — the same two scanners call it `app/requirements.txt` and
      `requirements.txt`.
    """
    parts = (
        finding.repo,
        finding.vuln_id,
        finding.package_name,
    )
    return hashlib.sha256("|".join(p.strip().lower() for p in parts).encode()).hexdigest()


def _major(version: str) -> int:
    """Leading integer of a version string, or -1 if it has none."""
    match = _VERSION_RE.search(version or "")
    if not match:
        return -1
    return int(match.group(1))


def is_major_bump(installed: str, fixed: str) -> bool:
    """True when moving to the fix crosses a major version boundary.

    Two deliberate refinements, both of which came out of real routing mistakes:

    * Unknown versions count as a major bump — unknown means a human looks at it.
    * **CalVer packages are not majors.** `certifi` goes 2021.5.30 → 2022.12.7, which a
      naive major comparison reads as a breaking change and hands to the LLM.  It is a
      root-certificate bundle with no API.  A leading component that looks like a year
      (≥1000) on both sides means calendar versioning, so the bump is mechanical.
    """
    a, b = _major(installed), _major(fixed)
    if a < 0 or b < 0:
        return True
    if a >= 1000 and b >= 1000:
        return False
    return b > a


def route_remediation(finding: Finding) -> str:
    """Decide which channel repairs this finding.  Plain code, no model call.

    Order matters — the first matching rule wins.
    """
    scanner = (finding.source_scanner or "").lower()
    klass = (finding.target_class or "").lower()
    artifact = (finding.artifact_type or "").lower()

    if scanner in _IAC_SCANNERS or klass in ("config", "terraform"):
        return "iac_fix"

    if scanner in _SAST_SCANNERS:
        # A logic change.  POC-PLAN.md §7 guardrails: SAST fixes ALWAYS get a human.
        return "ai_code_fix"

    if klass == "os-pkgs":
        # Same finding class, two different repair paths — which one depends on whether
        # the OS is baked into an image or installed on a VM.
        if artifact in ("container_image", "image"):
            return "base_image_bump"
        return "os_package"

    if not finding.fixed_version:
        # Nothing to bump to.  Becomes a work item or a risk acceptance (scenario 7),
        # never an AI patch attempt.
        return "none"

    if is_major_bump(finding.installed_version, finding.fixed_version):
        # A major bump can break callers, so it goes to Claude with the test suite as
        # the arbiter rather than being applied mechanically.
        return "ai_code_fix"

    return "dependency_bump"


def enrich(findings: Iterable[Finding]) -> list[Finding]:
    """Fill in severity, fingerprint and remediation channel."""
    out: list[Finding] = []
    for finding in findings:
        finding.severity = normalise_severity(finding.severity)
        if finding.severity == "UNKNOWN" and finding.cvss:
            finding.severity = severity_from_cvss(finding.cvss)
        finding.remediation_channel = route_remediation(finding)
        finding.fingerprint = fingerprint(finding)
        out.append(finding)
    return out


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates by fingerprint, keeping the highest-severity instance.

    Trivy reports the same CVE once per affected package target, and a repo scanned by
    both `trivy fs` and `pip-audit` yields the same advisory twice.
    """
    best: dict[str, Finding] = {}
    for finding in findings:
        key = finding.fingerprint or fingerprint(finding)
        current = best.get(key)
        if current is None or finding.severity_rank > current.severity_rank:
            best[key] = finding
    return sorted(
        best.values(),
        key=lambda f: (-f.severity_rank, f.repo, f.package_name, f.vuln_id),
    )


def summarise(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int], float]:
    """Counts by severity, counts by channel, and the mechanical-handling ratio."""
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    by_channel: dict[str, int] = {}
    mechanical = 0

    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_channel[finding.remediation_channel] = by_channel.get(finding.remediation_channel, 0) + 1
        if finding.is_mechanical:
            mechanical += 1

    ratio = round(mechanical / len(findings), 4) if findings else 0.0
    return by_severity, by_channel, ratio
