# `baobao-batch-worker` — Implementation Plan

> Demo target repo **#3 of 5** from [POC-PLAN.md](POC-PLAN.md) §1.
> This document is the plan; the rest of this repository is the implementation.

## 1. What this repo is, and why it exists

`baobao-batch-worker` is one of the purpose-built "dummy projects" that make up the
Ba0Ba0 POC target estate. It is **not** a throwaway stub — it is a small, genuinely
working Python service that gets scanned, patched, tested, deployed and rolled back by
the Ba0Ba0 control plane. Its job in the demo is to prove **one specific path** through
the system that no other repo in the estate covers.

From POC-PLAN.md §1:

| Repo | Stack | Azure service | Deliberate vulnerability | Remediation channel |
|---|---|---|---|---|
| `baobao-batch-worker` | Python 3.11 / Flask | **Container Apps job** | Old `debian:bookworm` base image + vulnerable pip packages | base-image bump · `requirements.txt` bump |

And from §2, it owns **CVE scenario 3**:

| # | Class | Example | Detected by | Patch channel | Gates hit | Verified by |
|---|---|---|---|---|---|---|
| 3 | **Container base image** | old Debian base in batch-worker | Trivy image scan | Dockerfile base bump | code review → CAB | image re-scan must show 0 criticals |

Three constraints from the plan shape every decision below:

1. **Purpose-built, not forked.** (§1) Juice Shop/NodeGoat are designed to *stay*
   vulnerable. We need vulnerabilities we can **pin, patch reproducibly, and re-seed**
   for every demo run. Hence `.baobao/seed.json` and `scripts/reseed.py`.
2. **A few hundred LOC.** (§1) Small enough that the AI patch agent's context pack is
   cheap and a human reviewer can read the whole diff.
3. **De-scope lever.** (§10) This repo is the *first thing dropped* if Week 2 slips,
   because its container scenario overlaps with `baobao-payments-api`. So it must be
   buildable in ~1 day and must not be a dependency of anything else.

## 2. What the worker actually does

A dummy app that does nothing is a bad patch target: there is no regression suite to
break, so CVE scenario 8 (failing patch → rollback) can't be demonstrated on it, and
the "red-then-green" evidence in §6 has nowhere to live.

So the worker does something the estate genuinely needs: it is the **nightly scanner
report ingestion job**. It reads raw scanner output (Trivy, pip-audit), normalises it,
dedupes it by fingerprint, persists it, and POSTs it to Ba0Ba0's
`/api/ingest/scanner` endpoint (POC-PLAN.md §5, `scan.yml` row).

```
manifest.yaml ──► fetch sources ──► parse ──► normalise ──► dedupe ──► persist ──► POST to Ba0Ba0
                  (path/URL/tar)    trivy      severity     sha256      Postgres    batched + retry
                                    pip-audit  + router     fingerprint
```

This choice buys four things:

- **A real regression suite.** Parser + normaliser + router are pure functions with
  meaningful tests. A bad patch breaks them → scenario 8 works here.
- **The blast-radius story.** (§1) It writes to the **shared Azure PostgreSQL Flexible
  Server**. When the IaC scenario hardens that server (public access off, TLS enforced),
  *this* app and `baobao-payments-api` are both impacted — which is what makes the
  impact-analysis screen do genuine work rather than decoration.
- **The deterministic strategy router, demonstrated.** (§7) `route_remediation()` is
  plain code, no LLM, and the run summary reports what fraction of findings were routed
  mechanically. That is the live evidence for the plan's "roughly 60% of findings never
  reach the LLM" claim.
- **Both container shapes.** The image runs as a **Container Apps Job** (scheduled batch)
  *and* as a long-lived Flask service (health + smoke-test target for `deploy.yml`).

## 3. Seeded vulnerabilities

Full machine-readable list in [`.baobao/seed.json`](.baobao/seed.json); human-readable
narrative in [SEEDED-VULNERABILITIES.md](SEEDED-VULNERABILITIES.md).

### 3.1 Base image (the headline — scenario 3)

`FROM python:3.11.4-slim-bookworm` — the June 2023 build. Trivy image scan reports
criticals in the Debian layer (`zlib` CVE-2023-45853, `libwebp` CVE-2023-4863, plus
glibc/perl/openssl highs). **Remediation channel: mechanical base-image bump** — no LLM.
Verification is a re-scan asserting `CRITICAL = 0`.

### 3.2 Vulnerable pip packages (`requirements.txt` bump)

Every pin is a real package version with a real published advisory, chosen so that it
**installs cleanly on Python 3.10–3.13 with no compiler** (pure-python or has current
wheels). This matters more than it sounds: a seed that won't `pip install` on a runner
costs a demo.

| Package | Pinned | Representative advisories | Fix |
|---|---|---|---|
| `Flask` | 2.0.1 | CVE-2023-30861 (session cookie cached by proxy) | ≥2.2.5 |
| `Werkzeug` | 2.0.3 | CVE-2023-25577, CVE-2023-46136, CVE-2024-34069 | ≥3.0.3 |
| `Jinja2` | 3.0.3 | CVE-2024-22195, CVE-2024-34064, CVE-2025-27516 | ≥3.1.6 |
| `requests` | 2.25.1 | CVE-2023-32681 (Proxy-Authorization leaked on redirect) | ≥2.32.4 |
| `urllib3` | 1.26.4 | CVE-2021-33503, CVE-2023-43804, CVE-2023-45803 | ≥2.5.0 |
| `idna` | 2.10 | CVE-2024-3651 (quadratic complexity DoS) | ≥3.7 |
| `certifi` | 2021.5.30 | CVE-2022-23491, CVE-2023-37920 (bad root CAs) | ≥2024.7.4 |
| `gunicorn` | 20.1.0 | CVE-2024-1135, CVE-2024-6827 (request smuggling) | ≥23.0.0 |
| `Pygments` | 2.7.4 | CVE-2021-27291 (ReDoS) | ≥2.15.0 |

`Pygments` is seeded deliberately **unreachable** — it is declared but never imported by
any runtime code path. That is the concrete instance of **CVE scenario 7 (false positive
/ risk-accepted)**: SCA flags it, reachability says no, the security lead records a
justification with an expiry rather than patching. Scenario 7 is called out in §2 as one
of the two that "matter most for credibility".

### 3.3 One reachable code-level vulnerability (bonus — scenario 2 shape)

`app/jobs/archive.py` calls `tarfile.extractall()` on scanner-artifact bundles with no
member validation — **CWE-22 path traversal**, the CVE-2007-4559 pattern. Bandit and
CodeQL both flag it. It is here for one reason: it is the only seeded vulnerability that
can be **proven exploited by a test**, which is what §6 calls "the single strongest
artifact in the whole demo":

- `tests/security/test_archive_traversal.py` writes a tar containing `../../pwned.txt`.
- Run against the **pre-patch** commit → the file escapes the extraction root → **RED**.
- Run against the patched commit → escape is refused → **GREEN**.

Because the seeded state is deliberately vulnerable, this test *must* fail on `main`.
It is therefore marked `@pytest.mark.security` and **excluded from the default pytest
run**, so `pytest` is green out of the box. CI runs it in a dedicated `verify-vulnerable`
job that asserts it fails, exactly as §6 step 2 describes.

### 3.4 Explicitly *not* seeded here

No SQL injection (that is `baobao-payments-api`, scenario 1/2), no XSS (that is
`baobao-customer-portal`), no OS-package or IaC findings (those are `baobao-legacy-vm`
and `baobao-infra`). Overlap would blur which repo proves which path.

## 4. Repository layout

```
.
├── IMPLEMENTATION-PLAN.md      this document
├── README.md                   how to run it, for a human
├── SEEDED-VULNERABILITIES.md   what is wrong on purpose, and how each is fixed
├── Dockerfile                  ← seeded: old bookworm base
├── requirements.txt            ← seeded: vulnerable pins
├── requirements-dev.txt        test/lint only, kept current
├── pyproject.toml              pytest markers, ruff, coverage
├── docker-compose.yml          local Postgres + worker
├── .env.example
├── .baobao/
│   ├── seed.json               machine-readable expected findings
│   └── patch-targets.md        the exact diff each channel should produce
├── app/
│   ├── config.py               env-driven config
│   ├── db.py                   SQLAlchemy Core, PostgreSQL (local dev · CI · Azure)
│   ├── models.py               Finding / JobRun dataclasses
│   ├── manifest.py             YAML job manifest loader (safe_load)
│   ├── normalise.py            severity map, fingerprint, dedupe, remediation router
│   ├── main.py                 Flask app factory + routes
│   ├── cli.py                  container entrypoint: `run` | `serve`
│   ├── jobs/
│   │   ├── runner.py           orchestrates a batch run
│   │   ├── archive.py          ← seeded: unsafe tar extraction
│   │   └── report.py           batched POST to Ba0Ba0, retry + backoff
│   └── parsers/
│       ├── trivy.py
│       └── pip_audit.py
├── samples/                    committed fixtures so the job runs with zero setup
├── scripts/
│   ├── reseed.py               restore the deliberate vulnerabilities
│   └── smoke.py                post-deploy smoke test used by deploy.yml
├── tests/
│   ├── unit/                   parsers, normaliser, router, manifest
│   ├── api/                    Flask routes
│   └── security/               red-then-green, excluded by default
└── .github/
    ├── CODEOWNERS              Gate 1 reviewer (app_owner persona, §9)
    └── workflows/{scan,ci,deploy}.yml
```

## 5. Data model

Two tables, mirroring POC-PLAN.md §3's `findings` shape so ingestion into the control
plane is a field-for-field copy rather than a translation:

- `job_runs` — `id, name, environment, started_at, finished_at, status, sources, findings_ingested, findings_new, mechanical_ratio, error`
- `findings` — `id, fingerprint (UNIQUE), job_run_id, repo, source_scanner, package_name, installed_version, fixed_version, vuln_id, severity, cvss, title, target, remediation_channel, first_seen, last_seen`

`fingerprint = sha256(repo|vuln_id|package)` gives idempotent re-ingestion: re-running
the same manifest updates `last_seen` and inserts nothing new. It deliberately excludes
the scanner and the target path, so the same advisory reported by both `trivy fs` and
`pip-audit` collapses to one row — the CAB should see one finding, not two. Upsert uses
`INSERT … ON CONFLICT(fingerprint) DO UPDATE` (PostgreSQL ≥9.5) — the same SQL runs on the
docker-compose dev server locally, in CI, and on the shared Postgres in Azure.

Timestamps are stored as ISO-8601 text and IDs as UUID strings, deliberately, so a finding
row is a verbatim copy of the JSON that ships to the control plane — no datetime coercion
between the DB, the payload, and the Ba0Ba0 store. This is a demo target, not the control
plane.

## 6. Remediation router (`normalise.route_remediation`)

Deterministic, no model call — the plain-code half of POC-PLAN.md §7:

| Condition | Channel | Mechanical? |
|---|---|---|
| Trivy `os-pkgs` on a container image | `base_image_bump` | ✅ |
| Trivy `os-pkgs` on a VM/filesystem target | `os_package` | ✅ |
| Checkov / tfsec source | `iac_fix` | ✅ |
| Lang package, fix available, same major | `dependency_bump` | ✅ |
| Lang package, fix requires a major bump | `ai_code_fix` | ❌ → Claude |
| SAST finding (CodeQL/Bandit) | `ai_code_fix` | ❌ → Claude |
| No fix version published | `none` — work item / risk acceptance | ✅ |

The run summary reports `mechanical_ratio`, which is the demo's live answer to *"are you
just letting an AI rewrite our code?"*

## 7. CI/CD

POC-PLAN.md §5 puts the real workflow bodies in a central `baobao-workflows` repo,
consumed via `workflow_call`. That repo does not exist yet, so the workflows here are
**self-contained and functional today**, with the one-line `uses:` replacement recorded
in a header comment for the Week-4 migration. A broken `uses:` pointing at a repo that
does not exist would make this repo un-demoable in the meantime.

| Workflow | Jobs |
|---|---|
| `scan.yml` | nightly + on-push: `pip-audit`, Trivy fs, Trivy image, Bandit → normalise → `POST /api/ingest/scanner` (GitHub OIDC token, audience `api://baobao` — **no shared secret**, §4 layer 2) |
| `ci.yml` | `test` (unit + api, JUnit XML uploaded) · `verify-vulnerable` (security tests, **expected to fail pre-patch** — the red-then-green evidence) · `build` (Buildx → ACR, Syft SBOM) |
| `deploy.yml` | `azure/login@v2` via OIDC → deploy to `test` → `staging` → `production`, each an environment-gated job; production is where the **custom deployment protection rule** pauses the run for Ba0Ba0's CAB approval; smoke test → auto-rollback to previous revision on failure |

Environment topology follows §1: one resource group, `test`/`staging`/`production` as
Container App revisions. `deploy.yml` sets revision suffixes accordingly and rolls back
by shifting traffic to the previous revision — which requires the app to be created in
**multiple revision mode** in Terraform (§5 gotcha; noted in the workflow comments so
`baobao-infra` gets it right).

Azure auth is OIDC federated credentials, one subject per repo+environment. **No
long-lived secrets in GitHub.** Repository variables carry non-secret coordinates
(`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, ACR name, RG, app name).

## 8. Verification — how we know this repo is done

Mapped to POC-PLAN.md §"Verification":

- **Local:** `pip install -r requirements.txt -r requirements-dev.txt` then `pytest` → green. `python -m app.cli run --manifest samples/job-manifest.yaml` → ingests the sample reports, prints a summary, exits 0.
- **Week 2:** `scan.yml` runs → Trivy + pip-audit report the seeded CVEs → they appear in the Ba0Ba0 dashboard within one scan cycle, correlated to this repo's asset, with `remediation_channel` already populated.
- **Week 3:** Ba0Ba0 routes the base-image finding mechanically → opens a real PR bumping the `FROM` line → approving in Ba0Ba0 posts a real GitHub PR review.
- **Week 4:** merged PR → `ci.yml` → `deploy.yml` reaches `production` → the run sits **blocked** pending Ba0Ba0's custom protection rule → CAB approves in the Ba0Ba0 UI → the Container App job image tag changes in Azure. Then force `scripts/smoke.py` to fail and confirm automatic rollback to the previous revision.
- **Week 5:** `scripts/reseed.py` restores the vulnerable state from a clean checkout in seconds, so the whole scenario replays from zero.

## 9. Deliberate non-goals

- **No auth.** This service sits behind the estate's network boundary and is invoked by
  Container Apps Jobs and smoke tests. Auth belongs in the Ba0Ba0 control plane (§3),
  not in a target app; adding it here would only add surface area to patch.
- **No migration tool.** Schema is created idempotently at startup. Two tables.
- **No Azure SDK calls from app code.** Everything Azure-facing lives in the workflows,
  so the app stays runnable on a laptop with no cloud credentials — which is what makes
  the demo rehearsable offline.
