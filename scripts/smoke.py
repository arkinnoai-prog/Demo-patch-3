#!/usr/bin/env python3
"""Post-deployment smoke test.

Run by `deploy.yml` against a freshly-deployed revision, before traffic is shifted to
it.  A non-zero exit triggers the automatic rollback described in POC-PLAN.md §5, and
is what makes CVE scenario 8 (failing patch → rollback) demonstrable on this repo.

    python scripts/smoke.py --base-url https://batch-worker--rev123.azurecontainerapps.io
    python scripts/smoke.py --base-url ... --expect-tag sha-a1b2c3d

Exit codes:  0 healthy · 1 a check failed · 2 unreachable
"""

from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

# Same reasoning as scripts/reseed.py: this runs on Windows consoles and in CI logs, and
# it must never fail on its own output — a smoke test that dies while printing looks
# identical to a failed deploy and would trigger a needless rollback.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_TTY = sys.stdout.isatty()
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def fetch(url: str, timeout: int) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(url, headers={"user-agent": "baobao-smoke"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            import json

            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        import json

        try:
            return exc.code, json.loads(exc.read().decode("utf-8"))
        except Exception:  # noqa: BLE001
            return exc.code, {}


def wait_for_ready(base_url: str, attempts: int, delay: float, timeout: int) -> bool:
    """A new Container Apps revision needs a moment before it answers."""
    for attempt in range(1, attempts + 1):
        try:
            status, _ = fetch(f"{base_url}/healthz", timeout)
            if status == 200:
                return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        if attempt < attempts:
            print(f"  … not up yet (attempt {attempt}/{attempts}), retrying in {delay:.0f}s")
            time.sleep(delay)
    return False


def main(argv: list[str] = None) -> int:
    parser = argparse.ArgumentParser(description="smoke-test a deployed revision")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--expect-tag", default="", help="assert /healthz reports this image tag")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--delay", type=float, default=6.0)
    args = parser.parse_args(argv)

    base_url = args.base_url.rstrip("/")
    print(f"smoke test → {base_url}\n")

    if not wait_for_ready(base_url, args.attempts, args.delay, args.timeout):
        print(f"  {RED}FAIL{RESET}  /healthz never returned 200 — revision is not serving")
        return 2

    failures: list[str] = []

    def check(name: str, fn: Callable[[], tuple[bool, str]]) -> None:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        marker = f"{GREEN}pass{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  {marker}  {name}{(' — ' + detail) if detail else ''}")
        if not ok:
            failures.append(name)

    def healthz() -> tuple[bool, str]:
        status, body = fetch(f"{base_url}/healthz", args.timeout)
        if status != 200:
            return False, f"HTTP {status}"
        if body.get("status") != "ok":
            return False, f"status={body.get('status')}"
        return True, f"version={body.get('version')} tag={body.get('image_tag')}"

    def image_tag() -> tuple[bool, str]:
        # The check that proves the deploy actually took, rather than trusting Azure's
        # own reported status — POC-PLAN.md's Week 4 verification asks for exactly this.
        _, body = fetch(f"{base_url}/healthz", args.timeout)
        actual = str(body.get("image_tag", ""))
        if actual != args.expect_tag:
            return False, f"serving {actual!r}, expected {args.expect_tag!r}"
        return True, actual

    def readyz() -> tuple[bool, str]:
        status, body = fetch(f"{base_url}/readyz", args.timeout)
        if status != 200:
            return False, f"HTTP {status} — database={body.get('database')}"
        return True, "database reachable"

    def metrics() -> tuple[bool, str]:
        status, body = fetch(f"{base_url}/metrics", args.timeout)
        if status != 200:
            return False, f"HTTP {status}"
        if "by_severity" not in body:
            return False, "unexpected payload shape"
        return True, ""

    def findings() -> tuple[bool, str]:
        status, body = fetch(f"{base_url}/api/findings?limit=1", args.timeout)
        if status != 200:
            return False, f"HTTP {status}"
        if "count" not in body:
            return False, "unexpected payload shape"
        return True, f"count={body['count']}"

    check("liveness  /healthz", healthz)
    if args.expect_tag:
        check("image tag matches deployment", image_tag)
    check("readiness /readyz", readyz)
    check("aggregates /metrics", metrics)
    check("query     /api/findings", findings)

    print()
    if failures:
        print(f"{RED}{len(failures)} check(s) failed{RESET} — "
              "deploy.yml will roll back this revision")
        return 1

    print(f"{GREEN}all checks passed{RESET} — safe to shift traffic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
