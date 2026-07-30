# Expected patches

The exact diff each remediation channel should produce for this repo. Ba0Ba0's patch
agent is not shown this file — it is the **grading key**: after a demo run, compare what
the agent actually opened against what is written here.

---

## 1 · `base_image_bump` — Dockerfile (scenario 3, the headline)

Mechanical. No LLM. One line.

```diff
-FROM python:3.11.4-slim-bookworm AS base
+FROM python:3.11-slim-bookworm AS base
```

Production-grade variant, once digest pinning is turned on in `baobao-infra`:

```diff
-FROM python:3.11.4-slim-bookworm AS base
+FROM python:3.11-slim-bookworm@sha256:<current-digest> AS base
```

**Verification:** re-scan the rebuilt image; `CRITICAL == 0` is the gate. `ci.yml`'s
build job already runs the re-scan and uploads the SARIF.

**Expected confidence:** high (≥85 — one line, no application code, full suite green), so
POC-PLAN.md §7's rules put this straight to a PR with CODEOWNERS review rather than a
draft.

---

## 2 · `dependency_bump` — requirements.txt

Mechanical for same-major fixes. The router sends the rest to Claude.

```diff
-Flask==2.0.1
-Werkzeug==2.0.3
-Jinja2==3.0.3
-requests==2.25.1
-urllib3==1.26.4
-idna==2.10
-certifi==2021.5.30
-gunicorn==20.1.0
+Flask==3.1.1
+Werkzeug==3.1.3
+Jinja2==3.1.6
+requests==2.32.4
+urllib3==2.5.0
+idna==3.10
+certifi==2025.7.14
+gunicorn==23.0.0
```

Three of these are **not** mechanical and the router should say so:

| Package | Why the router escalates it |
|---|---|
| `Werkzeug` 2.0.3 → 3.0.3 | major bump — Werkzeug 3 dropped `werkzeug.urls` helpers |
| `idna` 2.10 → 3.7 | major bump |
| `gunicorn` 20.1.0 → 22.0.0 | major bump — worker-config surface changed |

`certifi` 2021.5.30 → 2024.7.4 *looks* like a major bump and is not: certifi is CalVer
and carries no API. `normalise.is_major_bump` has an explicit CalVer rule for this. If a
demo run routes certifi to the LLM, that rule has regressed — it is a cheap, specific
thing to check on stage.

**Verification:** `pytest` green (the app imports Flask, Werkzeug, requests and
SQLAlchemy at runtime, so a bad bump breaks the API tests), then `pip-audit` clean.

---

## 3 · `none` → risk acceptance — Pygments (scenario 7)

**No patch.** The correct output is an exception record, not a PR.

```
Package:        Pygments 2.6.1
Advisories:     CVE-2021-27291, CVE-2022-40896 (ReDoS)
Reachability:   not imported by any module under app/  — `grep -ri pygments app/` is empty
Decision:       risk accepted
Approver:       security_analyst persona
Expiry:         90 days
Justification:  Unreachable from any runtime code path. Not exposed to untrusted input.
                Revisit at expiry or if a runtime import is introduced.
```

If the agent opens a PR bumping Pygments, that is a **demo failure to talk about, not
hide** — it is precisely the judgement gap scenario 7 exists to test.

---

## 4 · `ai_code_fix` — app/jobs/archive.py (the red-then-green artifact)

SAST finding. Mandatory human review, never auto-merged (POC-PLAN.md §7 guardrails).
The intended patch is small because `_is_within` is already written and tested — the
agent only has to call it:

```diff
-            # --- BEGIN SEEDED VULNERABILITY (CWE-22) ---------------------------
-            # No member path is validated against `dest_dir` before extraction.
-            # The fix is to filter members through `_is_within` (Python ≥3.12 also
-            # offers `filter="data"`).  See .baobao/patch-targets.md.
-            archive.extractall(path=dest_dir)  # nosec B202 - seeded on purpose
-            # --- END SEEDED VULNERABILITY --------------------------------------
-
-            names = [m.name for m in archive.getmembers() if m.isfile()]
+            safe_members = []
+            for member in archive.getmembers():
+                if member.issym() or member.islnk():
+                    raise ArchiveError(f"refusing link member in bundle: {member.name}")
+                if not _is_within(dest_dir, dest_dir / member.name):
+                    raise ArchiveError(f"refusing path traversal in bundle: {member.name}")
+                safe_members.append(member)
+
+            archive.extractall(path=dest_dir, members=safe_members)
+            names = [m.name for m in safe_members if m.isfile()]
```

Three properties a reviewer should insist on, and which the test enforces:

1. Absolute paths (`/etc/passwd`) are refused as well as `../` traversal.
2. Symlinks and hard links are refused — a link member is a traversal primitive even
   when its own path is inside the root.
3. It **raises** rather than silently skipping. A scanner bundle that contains a
   traversal entry is not a bundle to partially trust.

**Verification — the evidence artifact:**

```bash
git checkout <base-commit>
pytest -m security                       # RED  — the file escapes the extraction root
git checkout <patch-branch>
pytest -m security                       # GREEN — extraction refused
```

`ci.yml`'s `verify-vulnerable` job runs exactly this and fails the build if the security
test *passes* on the pre-patch commit, which is the failure mode where the AI writes a
test that passes trivially (POC-PLAN.md §6 step 2).

---

## 5 · Scenario 8 — the patch that must be rolled back

To rehearse rollback on this repo, seed a bad patch on a branch: change
`normalise.severity_from_cvss`'s CRITICAL threshold from `9.0` to `10.0`. It is a
one-character-class change, it looks harmless in review, and it breaks
`tests/unit/test_normalise.py::test_severity_from_cvss` — so CI blocks the merge, and
if force-merged, the deploy's smoke test fails and `deploy.yml` shifts traffic back to
the previous revision.
