"""Job manifest loading.

A manifest declares what a batch run ingests: which repos, which scanner outputs, and
where the normalised results go.  It is YAML because that is what the rest of the
estate's tooling emits.

Note `yaml.safe_load`, not `yaml.load`.  This file is intentionally NOT one of the
seeded vulnerabilities — the deserialisation sink here is reached by operator-supplied
config, which would make the seeded issue trivially exploitable rather than realistically
so.  The reachable code-level vulnerability in this repo lives in `app/jobs/archive.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_KINDS = ("trivy", "pip-audit")


class ManifestError(ValueError):
    """Raised when a manifest is missing, malformed, or references an unknown scanner."""


@dataclass
class Source:
    """One scanner output to ingest."""

    id: str
    repo: str
    kind: str
    path: str = ""
    url: str = ""
    archive: str = ""  # tar/tar.gz bundle of scanner artifacts
    member: str = ""  # which file inside `archive` to parse

    def __post_init__(self) -> None:
        if self.kind not in SUPPORTED_KINDS:
            raise ManifestError(
                f"source {self.id!r}: unsupported kind {self.kind!r} "
                f"(expected one of {', '.join(SUPPORTED_KINDS)})"
            )
        if not any((self.path, self.url, self.archive)):
            raise ManifestError(f"source {self.id!r}: needs one of path, url or archive")


@dataclass
class Manifest:
    name: str
    sources: list[Source] = field(default_factory=list)
    sink_endpoint: str = ""
    batch_size: int = 50
    fail_on_source_error: bool = False

    @property
    def source_count(self) -> int:
        return len(self.sources)


def parse_manifest(raw: dict[str, Any]) -> Manifest:
    if not isinstance(raw, dict):
        raise ManifestError("manifest root must be a mapping")

    job = raw.get("job") or {}
    if not isinstance(job, dict):
        raise ManifestError("`job` must be a mapping")

    name = str(job.get("name") or "scan-ingest").strip()

    raw_sources = raw.get("sources") or []
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ManifestError("manifest must declare at least one source")

    sources: list[Source] = []
    seen_ids = set()
    for index, entry in enumerate(raw_sources):
        if not isinstance(entry, dict):
            raise ManifestError(f"source #{index} must be a mapping")
        source_id = str(entry.get("id") or f"source-{index}")
        if source_id in seen_ids:
            raise ManifestError(f"duplicate source id {source_id!r}")
        seen_ids.add(source_id)

        repo = str(entry.get("repo") or "").strip()
        if not repo:
            raise ManifestError(f"source {source_id!r}: `repo` is required")

        sources.append(
            Source(
                id=source_id,
                repo=repo,
                kind=str(entry.get("kind") or "").strip(),
                path=str(entry.get("path") or ""),
                url=str(entry.get("url") or ""),
                archive=str(entry.get("archive") or ""),
                member=str(entry.get("member") or ""),
            )
        )

    sink = raw.get("sink") or {}
    if not isinstance(sink, dict):
        raise ManifestError("`sink` must be a mapping")

    batch_size = sink.get("batch_size", 50)
    try:
        batch_size = max(1, int(batch_size))
    except (TypeError, ValueError) as exc:
        raise ManifestError("`sink.batch_size` must be an integer") from exc

    return Manifest(
        name=name,
        sources=sources,
        sink_endpoint=str(sink.get("endpoint") or ""),
        batch_size=batch_size,
        fail_on_source_error=bool(job.get("fail_on_source_error", False)),
    )


def load_manifest(path: Path) -> Manifest:
    path = Path(path)
    if not path.is_file():
        raise ManifestError(f"manifest not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ManifestError(f"invalid YAML in {path}: {exc}") from exc
    return parse_manifest(raw)
