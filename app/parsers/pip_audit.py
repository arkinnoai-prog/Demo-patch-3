"""`pip-audit --format json` → `Finding`s.

pip-audit emits two shapes depending on version: a bare list of dependencies, or an
object with a `dependencies` key.  Both are accepted — a scanner upgrade on a runner
should not break ingestion silently.

pip-audit has no severity field at all.  Rather than invent one, findings are emitted as
UNKNOWN and left for `normalise.enrich` to resolve from CVSS if present.  Guessing here
would put fabricated severities in front of a CAB.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.models import Finding


def _dependencies(document: Any) -> Iterable[dict[str, Any]]:
    if isinstance(document, list):
        return [d for d in document if isinstance(d, dict)]
    if isinstance(document, dict):
        deps = document.get("dependencies") or []
        if isinstance(deps, list):
            return [d for d in deps if isinstance(d, dict)]
    return []


def _lowest_fix(fix_versions: Any) -> str:
    if isinstance(fix_versions, list) and fix_versions:
        return str(fix_versions[0])
    if isinstance(fix_versions, str):
        return fix_versions
    return ""


def parse(document: Any, repo: str) -> list[Finding]:
    findings: list[Finding] = []

    for dependency in _dependencies(document):
        name = str(dependency.get("name") or "").strip()
        installed = str(dependency.get("version") or "").strip()
        if not name:
            continue

        for vuln in dependency.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = str(vuln.get("id") or "").strip()
            if not vuln_id:
                continue

            # Prefer the CVE alias when pip-audit reports a GHSA id — the CAB and the
            # rest of the estate speak CVE.
            aliases = vuln.get("aliases") or []
            if isinstance(aliases, list):
                cve = next((str(a) for a in aliases if str(a).upper().startswith("CVE-")), "")
                if cve:
                    vuln_id = cve

            findings.append(
                Finding(
                    repo=repo,
                    source_scanner="pip-audit",
                    vuln_id=vuln_id,
                    severity="",
                    package_name=name,
                    installed_version=installed,
                    fixed_version=_lowest_fix(vuln.get("fix_versions")),
                    title=str(vuln.get("description") or "")[:500],
                    target="requirements.txt",
                    target_class="lang-pkgs",
                    artifact_type="repository",
                    primary_url=f"https://osv.dev/vulnerability/{vuln_id}",
                )
            )

    return findings
