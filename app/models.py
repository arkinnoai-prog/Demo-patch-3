"""Domain types.

`Finding` mirrors the `findings` table in POC-PLAN.md §3 field-for-field, so ingestion
into the Ba0Ba0 control plane is a copy rather than a translation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITY_ORDER = ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL")

REMEDIATION_CHANNELS = (
    "base_image_bump",
    "os_package",
    "dependency_bump",
    "iac_fix",
    "ai_code_fix",
    "none",
)

# Channels handled by plain code with no model call (POC-PLAN.md §7).
MECHANICAL_CHANNELS = ("base_image_bump", "os_package", "dependency_bump", "iac_fix", "none")


def utcnow() -> str:
    """ISO-8601 UTC timestamp.

    Stored as text rather than a native `timestamptz` so the finding row is a verbatim
    copy of what ships to the Ba0Ba0 control plane — no per-dialect datetime coercion
    between here, the JSON payload, and the control-plane store.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    """A single normalised vulnerability observation."""

    repo: str
    source_scanner: str
    vuln_id: str
    severity: str = "UNKNOWN"
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    title: str = ""
    target: str = ""
    target_class: str = ""  # trivy's Class: os-pkgs | lang-pkgs | config | secret
    artifact_type: str = ""  # container_image | filesystem | repository
    cvss: float | None = None
    primary_url: str = ""
    fingerprint: str = ""
    remediation_channel: str = "none"
    first_seen: str = field(default_factory=utcnow)
    last_seen: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def is_mechanical(self) -> bool:
        return self.remediation_channel in MECHANICAL_CHANNELS

    @property
    def severity_rank(self) -> int:
        try:
            return SEVERITY_ORDER.index(self.severity)
        except ValueError:
            return 0


@dataclass
class JobRun:
    """One execution of the ingestion job."""

    id: str
    name: str
    environment: str
    started_at: str
    finished_at: str = ""
    status: str = "running"  # running | succeeded | failed
    sources: int = 0
    findings_ingested: int = 0
    findings_new: int = 0
    mechanical_ratio: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunSummary:
    """What a batch run reports back to the operator and to Ba0Ba0."""

    run: JobRun
    findings: list[Finding] = field(default_factory=list)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_channel: dict[str, int] = field(default_factory=dict)
    reported: int = 0
    source_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run": self.run.to_dict(),
            "by_severity": self.by_severity,
            "by_channel": self.by_channel,
            "reported": self.reported,
            "source_errors": self.source_errors,
            "findings": [f.to_dict() for f in self.findings],
        }
