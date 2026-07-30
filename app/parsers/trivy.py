"""Trivy JSON (schema version 2) → `Finding`s.

Handles both `trivy image` and `trivy fs` output.  The distinction matters: an `os-pkgs`
result from an image scan is repaired by bumping the base image, while the same result
from a filesystem scan of a VM is repaired by an Ansible package upgrade.  That single
field is what makes the remediation router pick between two very different channels.
"""

from __future__ import annotations

from typing import Any

from app.models import Finding

_ARTIFACT_TYPES = {
    "container_image": "container_image",
    "image": "container_image",
    "filesystem": "filesystem",
    "fs": "filesystem",
    "repository": "repository",
    "vm": "vm",
}


def _artifact_type(document: dict[str, Any]) -> str:
    raw = str(document.get("ArtifactType") or "").strip().lower()
    return _ARTIFACT_TYPES.get(raw, raw)


def _best_cvss(entry: dict[str, Any]) -> float | None:
    """Highest v3 base score across the scoring sources Trivy reports.

    Trivy carries scores from nvd, redhat, ghsa and others; they disagree, and the
    conservative read is the highest.
    """
    cvss = entry.get("CVSS")
    if not isinstance(cvss, dict):
        return None

    scores: list[float] = []
    for vendor in cvss.values():
        if not isinstance(vendor, dict):
            continue
        for key in ("V3Score", "V40Score", "V2Score"):
            value = vendor.get(key)
            if isinstance(value, int | float):
                scores.append(float(value))
                break
    return max(scores) if scores else None


def parse(document: dict[str, Any], repo: str) -> list[Finding]:
    if not isinstance(document, dict):
        return []

    artifact_type = _artifact_type(document)
    artifact_name = str(document.get("ArtifactName") or "")
    results = document.get("Results") or []
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or artifact_name)
        target_class = str(result.get("Class") or "")

        for entry in result.get("Vulnerabilities") or []:
            if not isinstance(entry, dict):
                continue
            vuln_id = str(entry.get("VulnerabilityID") or "").strip()
            if not vuln_id:
                continue

            fixed = entry.get("FixedVersion") or ""
            # Trivy sometimes lists several fix candidates; the first is the minimum.
            if isinstance(fixed, str) and "," in fixed:
                fixed = fixed.split(",")[0].strip()

            findings.append(
                Finding(
                    repo=repo,
                    source_scanner="trivy",
                    vuln_id=vuln_id,
                    severity=str(entry.get("Severity") or ""),
                    package_name=str(entry.get("PkgName") or ""),
                    installed_version=str(entry.get("InstalledVersion") or ""),
                    fixed_version=str(fixed or ""),
                    title=str(entry.get("Title") or entry.get("Description") or "")[:500],
                    target=target,
                    target_class=target_class,
                    artifact_type=artifact_type,
                    cvss=_best_cvss(entry),
                    primary_url=str(entry.get("PrimaryURL") or ""),
                )
            )

    return findings
