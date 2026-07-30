# Seeded vulnerabilities

**This repository is deliberately vulnerable. That is its job.**

`baobao-batch-worker` is one of five purpose-built target repos in the Ba0Ba0 POC estate
([POC-PLAN.md §1](POC-PLAN.md)). It exists so the patch-automation pipeline has something
true to find, fix, test and deploy. Every issue below is intentional, pinned, and
restorable with `python scripts/reseed.py`.

> If you are here because a scanner flagged this repo: yes. That is the expected result.
> Do not hand-patch it — the whole point is that Ba0Ba0 raises the PR.

Machine-readable version: [`.baobao/seed.json`](.baobao/seed.json).
Expected diffs for each channel: [`.baobao/patch-targets.md`](.baobao/patch-targets.md).

---

## Why these, and not OWASP Juice Shop

POC-PLAN.md §1 makes the call explicitly: Juice Shop and NodeGoat are designed to *stay*
vulnerable — patching them breaks their challenges — and their CVE sets aren't
controllable. A demo needs vulnerabilities that can be **pinned, patched reproducibly,
and re-seeded before every run**. Hence a few hundred lines of purpose-built code and a
seed manifest.

---

## 1 · Old base image — the headline (CVE scenario 3)

**Where:** [`Dockerfile`](Dockerfile) · `FROM python:3.11.4-slim-bookworm`

The June 2023 build of Debian 12. A Trivy image scan finds criticals in the OS layer:

| CVE | Package | Severity |
|---|---|---|
| CVE-2023-45853 | zlib1g | CRITICAL |
| CVE-2023-4863 | libwebp7 | CRITICAL |
| CVE-2023-4911 | libc6 | HIGH |
| CVE-2023-5363 | libssl3 | HIGH |
| CVE-2023-31484 | perl-base | HIGH |

- **Detected by:** `trivy image`
- **Channel:** `base_image_bump` — **mechanical, no LLM**
- **Gates:** code review → CAB
- **Verified by:** image re-scan asserting `CRITICAL == 0`
- **Fix:** one line. `FROM python:3.11-slim-bookworm`

This is the scenario this repo owns. It is the cleanest possible demonstration that not
every remediation needs an AI — the router recognises an OS package finding on a
container image and rewrites the `FROM` line without a model call.

## 2 · Vulnerable pip pins

**Where:** [`requirements.txt`](requirements.txt)

| Package | Pinned | Advisories | Fix | Routes to |
|---|---|---|---|---|
| Flask | 2.0.1 | CVE-2023-30861 | 2.2.5 | `dependency_bump` |
| Werkzeug | 2.0.3 | CVE-2023-25577, CVE-2023-46136, CVE-2024-34069 | 2.2.3 / 3.0.3 | `dependency_bump` → `ai_code_fix` for the 3.x fix |
| Jinja2 | 3.0.3 | CVE-2024-22195, CVE-2024-34064, CVE-2025-27516 | 3.1.3 | `dependency_bump` |
| requests | 2.25.1 | CVE-2023-32681 | 2.31.0 | `dependency_bump` |
| urllib3 | 1.26.4 | CVE-2021-33503, CVE-2023-43804, CVE-2023-45803 | 1.26.18 | `dependency_bump` |
| idna | 2.10 | CVE-2024-3651 | 3.7 | `ai_code_fix` (major) |
| certifi | 2021.5.30 | CVE-2022-23491, CVE-2023-37920 | 2022.12.7 | `dependency_bump` (CalVer) |
| gunicorn | 20.1.0 | CVE-2024-1135, CVE-2024-6827 | 22.0.0 | `ai_code_fix` (major) |

Every one is pure-python or has current wheels, so `pip install -r requirements.txt`
resolves on Python 3.10–3.13 with no compiler. That is a deliberate constraint: a seed
that will not install on a runner costs a demo.

**certifi is the interesting one.** 2021.5.30 → 2022.12.7 *looks* like a major version
bump, and a naive router hands it to the LLM. certifi is CalVer and is a root-certificate
bundle with no API to break, so `normalise.is_major_bump` has an explicit rule for
year-shaped versions. If a demo run ever routes certifi to Claude, that rule has
regressed — a cheap, specific thing to check on stage.

## 3 · Unreachable dependency — CVE scenario 7

**Where:** [`requirements.txt`](requirements.txt) · `Pygments==2.6.1`

Flagged by SCA (CVE-2021-27291, CVE-2022-40896 — ReDoS) and **not imported by any runtime
code path in this service**. `grep -ri pygments app/` returns nothing;
`tests/security/test_seed_integrity.py` enforces that it stays that way.

- **Correct outcome:** a **risk acceptance with an expiry** — no PR, no patch.
- **Who decides:** the Security Analyst persona (POC-PLAN.md §9).
- **Why it matters:** POC-PLAN.md §2 calls scenarios 7 and 8 the two that matter most
  for credibility — they prove the system has judgement and a safety net, not just a
  happy path. If the agent opens a PR bumping Pygments, that is a demo failure worth
  talking about openly rather than hiding.

## 4 · Path traversal — the red-then-green evidence

**Where:** [`app/jobs/archive.py`](app/jobs/archive.py) · `extract_bundle()`

`tarfile.extractall()` with no member validation — CWE-22, the CVE-2007-4559 pattern. A
scanner-artifact bundle containing `../pwned.txt` writes outside the extraction root.
Verified exploitable, not merely flagged.

- **Detected by:** Bandit (B202), CodeQL (`py/tar-slip`)
- **Channel:** `ai_code_fix` — SAST findings **always** require human review
  (POC-PLAN.md §7 guardrails). Never auto-merged.
- **Proof:** [`tests/security/test_archive_traversal.py`](tests/security/test_archive_traversal.py)

This is the only seeded issue here that can be **proven exploited by a test**, which
makes it the evidence artifact POC-PLAN.md §6 calls "the single strongest artifact in the
whole demo":

```
pytest -m security   on main          →  RED    (3 failures — the vulnerability is real)
pytest -m security   on the patch     →  GREEN  (extraction refused)
```

`ci.yml`'s `verify-vulnerable` job asserts **both** halves, and fails the build if the
security test *passes* on the pre-patch commit — which is the failure mode where the AI
writes a test that passes trivially.

The correct fix is deliberately small: `_is_within()` is already written, tested and
correct in the same file; it is simply never called. That keeps the AI's diff to a few
lines, which is what earns a high deterministic confidence score (POC-PLAN.md §7).

## 5 · SQL injection — the full-stack demo's code vuln

**Where:** [`app/db.py`](app/db.py) · `search_findings()`, reached by `GET /api/findings?search=`
— the search box in the React UI.

The search term is concatenated into the SQL string instead of bound, so
`nomatch' OR '1'='1' --` returns **every** row and `… UNION SELECT …` reads arbitrary
columns. Verified exploitable by a test, not merely flagged.

- **Detected by:** Bandit (B608), CodeQL (`py/sql-injection`)
- **Channel:** `ai_code_fix` — SAST findings **always** require human review (POC-PLAN.md §7).
- **Proof:** [`tests/security/test_sql_injection.py`](tests/security/test_sql_injection.py)
  — RED on `main`, GREEN once the query is parameterised.

The correct fix is a two-line swap: `_search_findings_safe()` is already written, tested
and unused in the same file, so the AI's diff stays small — the same shape as §4.

> **Estate note.** POC-PLAN.md §1 originally assigned SQL injection to
> `baobao-payments-api`. It is seeded here **as well, on purpose**: this repo is also used
> as a standalone full-stack demo (React UI · Flask API · Postgres), and the findings
> search box is the natural, demoable place for it. When running the full five-repo
> estate, treat `baobao-payments-api` as the canonical owner and this as the local copy.

## 6 · Additional seeded findings (full-stack demo)

A broader, realistic surface so a scanning tool has plenty to find across SAST, secret and
reachability classes. Each is intentional and guarded by `pytest -m seed`; none is
auto-restored (they are code, not pins — restore with `git revert`).

| Class | Where | CWE | Detected by |
|---|---|---|---|
| SSRF | [`app/jobs/runner.py`](app/jobs/runner.py) `_load_document` | CWE-918 | CodeQL `py/full-ssrf` |
| TLS verification disabled | [`app/jobs/report.py`](app/jobs/report.py) `_post_with_retry` (`verify=False`) | CWE-295 | Bandit **B501**, CodeQL |
| Hardcoded credential | [`app/jobs/report.py`](app/jobs/report.py) `_DEV_FALLBACK_TOKEN` | CWE-798 | gitleaks · trufflehog · Trivy `secret` · Bandit **B105** |
| Flask debug mode | [`app/cli.py`](app/cli.py) `cmd_serve` (`debug=True`) | CWE-489 | CodeQL `py/flask-debug` · Semgrep |

- **SSRF** is reachable *unauthenticated*: `POST /api/jobs/run` accepts an inline manifest,
  and a source with a `url:` is fetched server-side with no allowlist — enough to reach
  `http://169.254.169.254/…` cloud metadata.
- **Hardcoded credential** is a **dummy** value, not a live token — it exists so a secret
  scanner has something to flag. Do not replace it with a real secret.
- **Flask debug** is not caught by Bandit through the `create_app()` factory, but CodeQL and
  Semgrep flag it. It affects only the `app.cli serve` dev server; production uses gunicorn.
- The tar-slip seed (§4) also lost its `# nosec B202`, so **Bandit now reports it** (B202) —
  the suppression had been hiding one of that seed's two declared detectors.

---

## Test markers — how green and red coexist

Three suites, two of them excluded from the default run, for opposite reasons:

| Command | On `main` | On a patch branch | What it means |
|---|---|---|---|
| `pytest` | 🟢 144 pass | 🟢 pass | the app genuinely works |
| `pytest -m security` | 🔴 6 fail | 🟢 pass | the vulnerabilities are real, then fixed |
| `pytest -m seed` | 🟢 pass | 🔴 fail | the seeds are still in place |

(The 6 failures are the three tar-slip cases in §4 plus the three SQL-injection cases in
§5; each suite's green-path companion passes on `main` too.)

`security` and `seed` must not share a marker: `pytest -m security` has to be able to go
green on a patch branch, and it could not if a seed-still-present check ran alongside it.

---

## Re-seeding between demo runs

```bash
python scripts/reseed.py --check    # report drift, change nothing (exit 1 if drifted)
python scripts/reseed.py            # restore Dockerfile + requirements.txt
python scripts/reseed.py --data     # also wipe the local findings database
```

Reads `.baobao/seed.json`; nothing is hardcoded. It writes with LF endings so a reseed
commit shows only the pins that actually moved, not a whole-file diff.

The **code** vulnerability (§4) is deliberately *not* auto-restored — re-introducing a
code vulnerability by script is something that should require someone to type
`git revert <the-patch-commit>` on purpose. `reseed.py` reports it and tells you how.

---

## Explicitly not seeded here

Overlap would blur which repo proves which path, so each target owns its scenarios:

| Not here | Lives in |
|---|---|
| Reflected XSS | `baobao-customer-portal` |
| OS / VM packages, Ansible remediation | `baobao-legacy-vm` (scenario 4) |
| IaC misconfiguration | `baobao-infra` (scenario 5) |

(SQL injection *was* listed here as belonging to `baobao-payments-api`; it is now also
seeded in this repo for the standalone full-stack demo — see §5.)

The one exception is the Pygments false positive (§3): scenario 7 is a *judgement*
scenario rather than a vulnerability class, and it needs a host repo. This one has the
cleanest unreachability argument in the estate.
