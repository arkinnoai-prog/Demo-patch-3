"""Scanner-output parsers.

Each parser turns one scanner's native JSON into a list of `Finding`s.  Adding a scanner
means adding a module here and one entry in `PARSERS` — normalisation, dedupe, routing
and persistence are shared and stay untouched.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.models import Finding
from app.parsers import pip_audit, trivy

PARSERS: dict[str, Callable[[dict[str, Any], str], list[Finding]]] = {
    "trivy": trivy.parse,
    "pip-audit": pip_audit.parse,
}


class UnknownScannerError(ValueError):
    pass


def parse(kind: str, document: dict[str, Any], repo: str) -> list[Finding]:
    parser = PARSERS.get(kind)
    if parser is None:
        raise UnknownScannerError(f"no parser registered for scanner {kind!r}")
    return parser(document, repo)


__all__ = ["PARSERS", "UnknownScannerError", "parse", "pip_audit", "trivy"]
