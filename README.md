# baobao-batch-worker

Scanner-report ingestion job for the Ba0Ba0 patch-automation estate.

> ⚠️ **This repo is deliberately vulnerable.** It is a purpose-built patch *target* — one
> of five in the Ba0Ba0 POC estate ([POC-PLAN.md §1](POC-PLAN.md)). The old base image and
> the pinned CVE-laden dependencies are there on purpose, so the pipeline has something
> true to find and fix. See [SEEDED-VULNERABILITIES.md](SEEDED-VULNERABILITIES.md) before
> "fixing" anything by hand.

| | |
|---|---|
| **Stack** | Python 3.11 · Flask · SQLAlchemy Core |
| **Azure service** | Container Apps **job** (scheduled) + Container App (API) |
| **Owns CVE scenario** | **3** — container base image · plus **7** — false positive / risk-accepted |
| **Remediation channels** | base-image bump · `requirements.txt` bump |
| **Plan** | [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) |

---

## What it does

The nightly job that turns raw scanner output into normalised findings for the Ba0Ba0
control plane.

```
manifest.yaml ─► fetch ─► parse ─► normalise ─► dedupe ─► persist ─► POST /api/ingest/scanner
                 path      trivy    severity    sha256    Postgres    batched, retried
                 url       pip-     + channel   finger-
                 tar       audit    router      print
```

It is a real service, not a stub, for three reasons:

- **It gives the pipeline a regression suite to break.** Parsers, normaliser and router
  are pure functions with meaningful tests, which is what makes CVE scenario 8 (patch
  breaks a test → auto-rollback) demonstrable here.
- **It shares the estate's Postgres.** The same server `baobao-payments-api` uses — so
  when the IaC scenario hardens it, the impact-analysis screen has a genuine blast radius
  rather than a decorative one.
- **It proves the "60% never reach the LLM" claim live.** Every run reports a
  `mechanical_ratio`. On the committed sample data it is **83%**.

## Quick start

```bash
python -m venv .venv && .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

docker compose up -d postgres                     # the dev database (PostgreSQL)

pytest                                            # 144 tests, green
python -m app.cli check                           # config + manifest + DB preflight
python -m app.cli run --manifest samples/job-manifest.yaml
```

No cloud credentials and no scanners needed — just the local Postgres above (the same
engine the estate runs) and the committed sample reports. If you already have a Postgres,
point `DATABASE_URL` at it instead of running compose. Output:

```
run          d7815bc1-c6fa-4cf3-aa03-17f762349a7c
manifest     nightly-scan-ingest
status       succeeded
sources      3
findings     23 (23 new)
mechanical   83% routable without an LLM
severity     UNKNOWN=10  LOW=1  MEDIUM=3  HIGH=6  CRITICAL=3
channels     base_image_bump=7  dependency_bump=11  ai_code_fix=4  none=1
```

Run it twice — the second run reports `(0 new)`. Ingestion is idempotent by fingerprint,
which is what keeps the dashboard's "new since last scan" figure meaningful.

### API mode

```bash
python -m app.cli serve --port 8080
```

| Route | Purpose |
|---|---|
| `GET /` | the React UI (when built); otherwise a JSON pointer to the API |
| `GET /healthz` | liveness — does **not** touch the DB, so a Postgres blip cannot kill a healthy revision. Reports the deployed `image_tag`. |
| `GET /readyz` | readiness — *does* check the DB (503 when unreachable) |
| `GET /metrics` | aggregates by severity / channel / repo / scanner |
| `POST /api/jobs/run` | run the job synchronously; body `{"manifest": "<path>"}` or an inline manifest |
| `GET /api/jobs`, `GET /api/jobs/<id>` | run history |
| `GET /api/findings?repo=&severity=&channel=&limit=` | findings, worst first |
| `GET /api/findings?search=<text>` | free-text search — ⚠️ **seeded SQL-injection sink** (CWE-89), the search box the UI uses |

### Frontend (React UI)

A React + Vite single-page app in [`frontend/`](frontend/) is the operator UI — a dashboard
(severity/channel/run stats) and a searchable findings table. Flask serves the built bundle
at `/`, so **one container answers both the API and the UI on port 8080** — nothing to split
for Azure.

```bash
cd frontend && npm install && npm run build     # outputs frontend/dist/, served by Flask at /
npm run dev                                      # or: hot-reload dev server, proxies API to :8080
```

The Docker image builds the frontend in a discarded Node stage and copies only the static
bundle in, so the deployed image ships no Node and the Trivy scan still sees the seeded base
image. The findings **search box** is wired to the seeded SQL-injection endpoint above — the
demoable code vulnerability a SAST scan (Bandit B608 / CodeQL `py/sql-injection`) reports.

### Docker

```bash
docker build -t baobao-batch-worker:local .
docker run -p 8080:8080 -e IMAGE_TAG=sha-local baobao-batch-worker:local        # API mode
docker run --rm baobao-batch-worker:local python -m app.cli run \
    --manifest samples/job-manifest.yaml                                        # job mode
```

Both shapes come from one image — the Container Apps Job just overrides the command.
`docker compose up` brings up Postgres alongside it; `docker compose run --rm job`
exercises the batch shape against it.

## Layout

```
app/
  config.py       env-driven config
  db.py           SQLAlchemy Core (PostgreSQL); ⚠️ seeded CWE-89 in search_findings
  models.py       Finding / JobRun — mirrors POC-PLAN.md §3 field-for-field
  manifest.py     YAML job manifest (safe_load)
  normalise.py    severity, fingerprint, dedupe, and the remediation router
  main.py         Flask app factory
  cli.py          container entrypoint — run | serve | check
  jobs/
    runner.py     orchestration
    archive.py    ⚠️ seeded CWE-22 — the red-then-green artifact
    report.py     batched POST to Ba0Ba0, retry + backoff
  parsers/        trivy.py · pip_audit.py
frontend/         React + Vite SPA (the operator UI) — served by Flask at /
samples/          committed fixtures — zero-setup runs
scripts/          reseed.py · smoke.py
tests/            unit · api · security
.baobao/          seed.json · patch-targets.md
```

## The remediation router

Plain code, no model call — the deterministic half of POC-PLAN.md §7. First match wins:

| Condition | Channel | Mechanical |
|---|---|---|
| Checkov / tfsec source, or a `config` target | `iac_fix` | ✅ |
| CodeQL / Bandit / Semgrep source | `ai_code_fix` | ❌ human review mandatory |
| `os-pkgs` on a container image | `base_image_bump` | ✅ |
| `os-pkgs` on a VM / filesystem | `os_package` | ✅ |
| No fix version published | `none` — work item or risk acceptance | ✅ |
| Fix crosses a major version | `ai_code_fix` | ❌ |
| Otherwise | `dependency_bump` | ✅ |

## Tests

```bash
pytest                  # 145 unit + api tests — green (needs Postgres; see Quick start)
pytest -m security      # RED on main by design; GREEN once patched
pytest -m seed          # asserts the seeds are still in place — GREEN on main
ruff check app tests scripts
```

The `security` suite **is supposed to fail here**. It asserts the *fixed* behaviour of the
seeded code vulnerabilities (path traversal, SQL injection), so its failure on `main` and
its pass on a patch branch is the red-then-green evidence. These suites are run locally /
by the client's pipeline — GitHub Actions here only deploys (see CI/CD below).

## CI/CD

GitHub does exactly one thing here: **build and deploy on a tag.** The seeded
vulnerabilities are intentional and are meant to be found by the **client's scanner
against the deployed app**, not flagged by GitHub — so there is no scanning workflow.

| Workflow | Does |
|---|---|
| [`deploy.yml`](.github/workflows/deploy.yml) | on a `v*` tag (or manual run): build the image (React + Flask, one multi-stage Dockerfile) → push to **GHCR** → `az containerapp update` → health-check `/healthz` |

```
git tag v1.0.0 && git push origin v1.0.0   →   build → GHCR → Azure Container Apps → live URL
```

**No stored secrets** — Azure auth is OIDC federated credentials; the GHCR push uses the
built-in `GITHUB_TOKEN`. The infrastructure is a reusable **Bicep** template under
[`infra/`](infra/) that provisions a Singapore (`southeastasia`) resource group shared by
all three demo repos. Full setup — provisioning, OIDC wiring, and the first deploy — is in
**[DEPLOYMENT.md](DEPLOYMENT.md)**.

## Configuration

Copy [`.env.example`](.env.example) to `.env`. Everything is environment-driven so one
image runs as a Job, as a Container App, and on a laptop with no cloud access.

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `local` | `test` \| `staging` \| `production` \| `local` |
| `DATABASE_URL` | `postgresql+psycopg2://baobao:localdev@localhost:5432/baobao` | the docker-compose dev server; Azure: the shared Postgres Flexible Server |
| `BAOBAO_INGEST_URL` | *(blank)* | blank = persist locally, post nothing |
| `IMAGE_TAG` | `dev` | set by the deploy script; surfaced on `/healthz` so the smoke test can prove the new revision is the one serving |
| `JOB_MANIFEST` | `samples/job-manifest.yaml` | |
| `DRY_RUN` | `false` | skip the control-plane POST |

## Re-seeding between demos

```bash
python scripts/reseed.py --check    # report drift (exit 1 if drifted)
python scripts/reseed.py            # restore the seeded vulnerable state
```

Source of truth is [`.baobao/seed.json`](.baobao/seed.json).
