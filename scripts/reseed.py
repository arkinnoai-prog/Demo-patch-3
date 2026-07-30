#!/usr/bin/env python3
"""Restore this repo's deliberate vulnerabilities.

POC-PLAN.md §1 requires vulnerabilities we can "pin, patch reproducibly, and **re-seed
for every demo**".  After a demo run has merged the AI's base-image bump and dependency
bumps, this puts the repo back to its seeded state so the whole scenario replays.

    python scripts/reseed.py --check     # report drift, change nothing (exit 1 if drifted)
    python scripts/reseed.py             # restore Dockerfile + requirements.txt
    python scripts/reseed.py --data      # also wipe the local findings database

Source of truth is .baobao/seed.json.  Nothing is hardcoded here.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_FILE = REPO_ROOT / ".baobao" / "seed.json"

# A Windows console defaults to cp1252, which cannot encode the arrows this script
# prints — and an unhandled UnicodeEncodeError while resetting a demo is a bad minute to
# have.  Force UTF-8 on stdout, and fall back rather than raising if it is still refused.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Colour only when attached to a terminal; piping to a file or a CI log should not embed
# escape codes.
_TTY = sys.stdout.isatty()
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def _write(path: Path, text: str) -> None:
    """Write without translating line endings.

    `Path.write_text` defaults to os.linesep on Windows, which would rewrite every line
    of requirements.txt as CRLF and turn a reseed into a whole-file diff on GitHub.  The
    reseed commit should show only the pins that actually moved.
    """
    path.write_text(text, encoding="utf-8", newline="\n")


def load_seed() -> dict:
    return json.loads(SEED_FILE.read_text(encoding="utf-8"))


def seed_entry(seed: dict, seed_id: str) -> dict:
    return next(s for s in seed["seeds"] if s["id"] == seed_id)


def check_base_image(seed: dict) -> tuple[bool, str, str]:
    entry = seed_entry(seed, "base-image")
    dockerfile = REPO_ROOT / entry["file"]
    text = dockerfile.read_text(encoding="utf-8")

    # Target the runtime stage (`... AS base`), not the frontend build stage that now
    # precedes it in the multi-stage Dockerfile.  Fall back to the first FROM for a
    # single-stage file.
    match = re.search(r"^FROM\s+(\S+)\s+AS\s+base", text, re.MULTILINE) or re.search(
        r"^FROM\s+(\S+)", text, re.MULTILINE
    )
    current = match.group(1) if match else "(no FROM found)"
    return current == entry["current"], current, entry["current"]


def restore_base_image(seed: dict) -> bool:
    entry = seed_entry(seed, "base-image")
    dockerfile = REPO_ROOT / entry["file"]
    text = dockerfile.read_text(encoding="utf-8")

    # Rewrite only the runtime `AS base` stage, so the frontend build stage is untouched.
    patched, count = re.subn(
        r"^FROM\s+\S+(\s+AS\s+base)",
        rf"FROM {entry['current']}\1",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if not count:  # single-stage Dockerfile with no `AS base`
        patched, count = re.subn(
            r"^FROM\s+\S+", f"FROM {entry['current']}", text, count=1, flags=re.MULTILINE
        )
    if count and patched != text:
        _write(dockerfile, patched)
        return True
    return False


def check_pins(seed: dict) -> list[tuple[str, str, str]]:
    """Return [(package, found, expected)] for every pin that has drifted."""
    requirements = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
    drifted: list[tuple[str, str, str]] = []

    packages = list(seed_entry(seed, "pip-pins")["packages"])
    unreachable = seed_entry(seed, "unreachable-dep")
    packages.append({"name": unreachable["package"], "pinned": unreachable["pinned"]})

    for package in packages:
        match = re.search(
            rf"^{re.escape(package['name'])}==(\S+)",
            requirements,
            re.MULTILINE | re.IGNORECASE,
        )
        found = match.group(1) if match else "(absent)"
        if found != package["pinned"]:
            drifted.append((package["name"], found, package["pinned"]))

    return drifted


def restore_pins(seed: dict) -> int:
    path = REPO_ROOT / "requirements.txt"
    text = path.read_text(encoding="utf-8")
    restored = 0

    packages = list(seed_entry(seed, "pip-pins")["packages"])
    unreachable = seed_entry(seed, "unreachable-dep")
    packages.append({"name": unreachable["package"], "pinned": unreachable["pinned"]})

    for package in packages:
        pattern = rf"^({re.escape(package['name'])})==\S+"
        replacement = rf"\g<1>=={package['pinned']}"
        text, count = re.subn(pattern, replacement, text, flags=re.MULTILINE | re.IGNORECASE)
        restored += count

    _write(path, text)
    return restored


def check_code_vuln(seed: dict) -> bool:
    entry = seed_entry(seed, "tar-traversal")
    source = (REPO_ROOT / entry["file"]).read_text(encoding="utf-8")
    return "extractall(path=dest_dir)" in source


def check_sql_injection(seed: dict) -> bool:
    entry = seed_entry(seed, "sql-injection")
    source = (REPO_ROOT / entry["file"]).read_text(encoding="utf-8")
    return "LIKE '%{term}%'" in source


# The extra full-stack-demo findings: (label, file, marker string that must be present).
_ADDITIONAL_SINKS = [
    ("SSRF (CWE-918)", "app/jobs/runner.py", "requests.get(source.url"),
    ("insecure TLS (CWE-295)", "app/jobs/report.py", "verify=False"),
    ("hardcoded token (CWE-798)", "app/jobs/report.py", "_DEV_FALLBACK_TOKEN"),
    ("Flask debug (CWE-489)", "app/cli.py", "debug=True"),
]


def check_additional_sinks() -> list[tuple[str, str, bool]]:
    """[(label, file, present)] for the extra seeded code/secret findings."""
    out = []
    for label, rel, needle in _ADDITIONAL_SINKS:
        present = needle in (REPO_ROOT / rel).read_text(encoding="utf-8")
        out.append((label, rel, present))
    return out


def wipe_data() -> None:
    data_dir = REPO_ROOT / "data"
    if data_dir.exists():
        shutil.rmtree(data_dir)
        print(f"  {GREEN}reset{RESET}  removed ./data (local findings database)")
    else:
        print(f"  {GREEN}ok{RESET}     ./data already clean")


def main(argv: list[str] = None) -> int:
    parser = argparse.ArgumentParser(description="restore the seeded vulnerable state")
    parser.add_argument("--check", action="store_true", help="report drift without changing files")
    parser.add_argument("--data", action="store_true", help="also wipe the local database")
    args = parser.parse_args(argv)

    seed = load_seed()
    print(f"{seed['repo']} — seed check ({SEED_FILE.relative_to(REPO_ROOT)})\n")

    drifted = False

    # --- base image --------------------------------------------------------
    ok, found, expected = check_base_image(seed)
    if ok:
        print(f"  {GREEN}ok{RESET}     base image  {found}")
    else:
        drifted = True
        print(f"  {RED}drift{RESET}  base image  {found}  →  should be {expected}")
        if not args.check and restore_base_image(seed):
            print(f"  {GREEN}fixed{RESET}  Dockerfile FROM restored")

    # --- pinned dependencies ----------------------------------------------
    pins = check_pins(seed)
    if not pins:
        print(f"  {GREEN}ok{RESET}     requirements.txt  all seeded pins present")
    else:
        drifted = True
        for name, found, expected in pins:
            print(f"  {RED}drift{RESET}  {name}  {found}  →  should be {expected}")
        if not args.check:
            print(f"  {GREEN}fixed{RESET}  restored {restore_pins(seed)} pin(s)")

    # --- code vulnerability ------------------------------------------------
    # Deliberately NOT auto-restored.  Re-introducing a code vulnerability by script is
    # the kind of thing that should require someone to type `git revert` on purpose.
    if check_code_vuln(seed):
        print(f"  {GREEN}ok{RESET}     app/jobs/archive.py  CWE-22 sink present")
    else:
        drifted = True
        entry = seed_entry(seed, "tar-traversal")
        print(f"  {YELLOW}drift{RESET}  {entry['file']}  the seeded CWE-22 has been patched")
        print("         restore it deliberately:  git revert <the-patch-commit>")

    # --- code vulnerability: SQL injection ---------------------------------
    # Same policy as the traversal sink — reported, never auto-restored by script.
    if check_sql_injection(seed):
        print(f"  {GREEN}ok{RESET}     app/db.py  CWE-89 sink present")
    else:
        drifted = True
        entry = seed_entry(seed, "sql-injection")
        print(f"  {YELLOW}drift{RESET}  {entry['file']}  the seeded CWE-89 has been patched")
        print("         restore it deliberately:  git revert <the-patch-commit>")

    # --- additional code / secret findings ---------------------------------
    # Reported, never auto-restored (they are code, not pins).
    for label, rel, present in check_additional_sinks():
        if present:
            print(f"  {GREEN}ok{RESET}     {rel}  {label} present")
        else:
            drifted = True
            print(f"  {YELLOW}drift{RESET}  {rel}  seeded {label} has been patched")
            print("         restore it deliberately:  git revert <the-patch-commit>")

    if args.data:
        wipe_data()

    print()
    if args.check:
        print("drifted — reseed needed" if drifted else "seed intact")
        return 1 if drifted else 0

    print("reseed complete" if drifted else "nothing to do — seed already intact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
