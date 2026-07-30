# Ba0Ba0 — Mock Demo → Working POC

## Context

`ICOMPAZ-PATCH` today is a **Next.js 16 demo** of the BaoBao patch-automation platform described in the client SOW email (*"Meeting with BaOBaO @iCompaz — Patch works using AI"*, 10 Jul 2026). The SOW promises to cut the monthly patch cycle from **~30 days to 14**, keeping governance, approvals and production safety intact.

The repo's own [docs/requirements-alignment.md](docs/requirements-alignment.md) grades the demo honestly:

| SOW stage | Today |
|---|---|
| **Days 1–6** — ingest → AI triage → impact graph → CAB → test plan | ✅ genuinely live (Gemini structured output) |
| **Days 7–14** — CI/CD, test execution, staged deploy, closure, audit | ▢ **simulated** |

That "simulated" half is theatre, and it is exactly what the client will probe:

- [components/deploy/deploy-run.tsx](components/deploy/deploy-run.tsx#L50-L117) — a hardcoded GitHub Actions replay (`RUN_NUMBER = 128`, fixed `ms` timings, canned log strings). It simulates **Google Cloud Run**, not Azure.
- [components/deploy/ansible-run.tsx](components/deploy/ansible-run.tsx) — 28 fixed lines; **ignores its `vuln` prop entirely**, always patches the same two Windows hosts.
- [components/deploy/code-review.tsx](components/deploy/code-review.tsx) — synthesises a fake Dockerfile diff.
- Approvals on [app/(app)/cab/page.tsx](app/(app)/cab/page.tsx) are `useState` and are **never persisted**.
- The entire dataset lives in one React context persisted to **localStorage** ([lib/store/data-provider.tsx](lib/store/data-provider.tsx#L22)). Single-browser, single-user, no integrity.
- There is **no `.github/` directory, no CI, no tests, no auth, no database** anywhere in the repo.

**Goal of this POC:** make Days 7–14 real. Ba0Ba0 stops *depicting* a control plane and becomes one — driving real GitHub Actions pipelines that deploy real patches to a real (small) Azure estate, through **test → staging → production**, with human approval gates that genuinely block deployment, and an audit trail that survives a refresh.

**The single most important architectural move:** Ba0Ba0 is registered as a **GitHub App implementing a [custom deployment protection rule](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/creating-custom-deployment-protection-rules)**. When a workflow reaches the `production` environment, GitHub calls *our* webhook and waits. The CAB approval clicked in the Ba0Ba0 UI is what releases it. That converts the SOW's central claim — *"automation with governance and human approval intact"* — from a slide into something demonstrable, and it is the one thing a competitor's demo cannot fake.

---

## Confirmed constraints

| Decision | Choice |
|---|---|
| Azure | **Real, lean estate.** Terraform-provisioned, ~$80–150/mo, one subscription. |
| GitHub | **Existing enterprise org** (name TBD — see Prerequisites). |
| Backend | **Postgres + real auth.** Drizzle, Entra ID SSO, RBAC, append-only audit log. |
| Timeline | **4–5 weeks.** |
| Gates | Human-in-the-loop at test → staging → production. |

---

## Prerequisites to confirm before Week 1

These are hard blockers, listed first because two of them can invalidate the design.

1. **GitHub plan must be Enterprise Cloud, not Team.** Environment protection rules — *required reviewers* and *custom deployment protection rules* — are only available on **private** repos under **GitHub Enterprise**. On Free/Pro/Team they work only on public repos ([GitHub Docs](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)). If the org is on Team, we must either upgrade, or make the four dummy repos public (acceptable — they contain no client IP).
2. **Azure subscription + permissions** — ability to create an App Registration with federated credentials (for OIDC) and assign Contributor on a resource group.
3. **Entra ID tenant** for SSO, and permission to register the Ba0Ba0 app.
4. **Anthropic API key** for patch generation (see AI architecture).
5. Rotate the Gemini key in the local `.env`. *(Verified: `.env` was never committed and is correctly gitignored — no git-history leak, but it should not follow the repo into CI.)*

---

## 1. Target estate — the dummy projects

Four purpose-built repos, each exercising a **different Azure service** and, more importantly, a **different remediation channel**. All under `<org>/baobao-demo-*`.

> **Design decision:** build these small and purpose-built rather than forking OWASP Juice Shop/NodeGoat. Those are designed to *stay* vulnerable (patching breaks their challenges) and their CVE sets aren't controllable. We need vulnerabilities we can pin, patch reproducibly, and re-seed for every demo. Each app is a few hundred LOC.

| Repo | Stack | Azure service | Deliberate vulnerability | Remediation channel |
|---|---|---|---|---|
| `baobao-payments-api` | Node 20 / Express / TS | **Container Apps** (revisions = envs) | Pinned vulnerable npm deps + a SQL-injection route | dependency-bump PR · AI code-fix PR |
| `baobao-customer-portal` | Next.js / React | **App Service** (deployment slots = envs) | Reflected XSS + outdated framework dep | AI code-fix PR — **Playwright UI test target** |
| `baobao-batch-worker` | Python 3.11 / Flask | **Container Apps** job | Old `debian:bookworm` base image + vulnerable pip packages | base-image bump · `requirements.txt` bump |
| `baobao-legacy-vm` | Ubuntu 22.04 + nginx | **Azure VM (IaaS)** | Outdated OS packages (openssl/nginx) | **Ansible playbook** — the real version of `ansible-run.tsx` |
| `baobao-infra` | Terraform | *the estate itself* | Public storage container, NSG `0.0.0.0/0`, TLS 1.0 | IaC fix PR (Checkov-gated) |

Shared tier: **Azure PostgreSQL Flexible Server**, **Key Vault**, **Log Analytics**. The Postgres server is deliberately dual-purpose — it's a *patch target* (the IaC scenario hardens it: public access off, TLS enforced) **and** the blast-radius proof, since one change touches two applications and three stakeholder groups. That makes the impact-analysis screen do genuine work rather than decoration.

**Ba0Ba0's own control-plane database goes on Neon, not Azure.** It saves ~$18/mo, but the real reason is that **Neon branch reset restores the entire application state in ~5 seconds** — which is what makes the demo reliably repeatable. Highest-leverage infra decision in the plan.

**Environment topology (lean):** one resource group. `test` and `staging` are App Service slots / Container App revisions; `production` is the live slot/revision. This gives real, independently-deployable environments and real slot-swap rollback without paying for three estates.

> ⚠️ The Ansible path needs network reachability from the GitHub runner to the VM. Simplest for a POC: public IP + NSG allowlisted to GitHub's runner ranges, SSH key in Key Vault. Flagged as a Week-2 risk.

---

## 2. CVE scenario matrix

Eight scenarios, each proving a **different path** through the system. This is what makes the demo answer *"can you handle all of it?"*

| # | Class | Example | Detected by | Patch channel | Gates hit | Verified by |
|---|---|---|---|---|---|---|
| 1 | **SCA dependency** | vulnerable npm lib in payments-api | `npm audit` / Trivy | version bump PR | code review → CAB | unit + API tests |
| 2 | **SAST code vuln** | SQLi in payments-api | CodeQL | **AI-authored code fix** PR | code review (mandatory human) → CAB | new regression test proving the fix |
| 3 | **Container base image** | old Debian base in batch-worker | Trivy image scan | Dockerfile base bump | code review → CAB | image re-scan must show 0 criticals |
| 4 | **OS / VM package** | openssl on legacy-vm | Trivy VM scan / `apt` | **Ansible playbook** | infra approval → CAB | post-patch version assertion |
| 5 | **IaC misconfiguration** | public storage, open NSG | Checkov / tfsec | Terraform PR | infra approval → CAB | `terraform plan` + re-scan |
| 6 | **Emergency / e-CAB** | internet-facing + exploit available, CVSS 9.8 | any source | fast-tracked | **compressed**: skips standard CAB → e-CAB, 2 approvers | canary + smoke tests |
| 7 | **False positive / risk-accepted** | flagged dep not reachable | SCA | **none** — human overrides AI | security lead records justification | exception recorded with expiry |
| 8 | **Failing patch → rollback** | patch breaks a test | CI | auto-revert | blocked at gate | rollback proves the safety story |

Scenarios **7 and 8 matter most for credibility** — they prove the system has judgement and a safety net, not just a happy path. The existing `PatchRun` component already deliberately fails at a "change-policy gate" ([analysis/page.tsx](app/(app)/analysis/page.tsx)), so the UX intent is there; we make it real.

---

## 3. Backend: persistence, auth, domain model

**Stack additions:** Drizzle ORM + `postgres` driver, Auth.js v5 (Entra ID provider), Octokit (`@octokit/app`, `@octokit/rest`), `@anthropic-ai/sdk`.

The existing Zod schemas in [lib/ai/schemas.ts](lib/ai/schemas.ts) become the source of truth for the DB schema and API contracts — they are well-designed and should be **extended, not replaced**. Required changes: the `environment` enum (`production|staging|development`) becomes `test|staging|production`; `vulnStatus` expands into the lifecycle states below.

**New tables** (beyond the existing asset/application/finding entities):

| Table | Purpose |
|---|---|
| `repositories`, `environments` | maps a repo → its GitHub environments → its Azure resource |
| `findings` | extends `vulnerabilitySchema` + `source_scanner`, `fingerprint` (dedupe), `remediation_channel`, `first_seen`/`last_seen` |
| `changes` | the lifecycle record — change id, type (`standard|normal|emergency`), stage, risk, window |
| `approvals` | `change_id`, `gate`, `role`, `user_id`, `decision`, `comment`, `decided_at` |
| `patch_runs`, `pull_requests` | AI patch attempts, generated diff, confidence, resulting PR |
| `workflow_runs`, `deployments` | mirrored GitHub Actions state, canary traffic %, rollback flag |
| `test_runs` | suite (`unit｜api｜ui｜security｜smoke`), pass/fail counts, JUnit + artifact links |
| `evidence_artifacts` | kind, blob URL, sha256 — the audit pack contents |
| `exceptions` | risk acceptance: justification, approver, expiry (scenario 7) |
| `audit_events` | **append-only, hash-chained** (`prev_hash`/`hash`) — tamper-evident, satisfies SOW capability (k) |

**Change state machine** — this *is* the 14-day model, and it drives the lifecycle board:

```
ingested → triaged → impact_assessed → patch_generating → patch_ready
   │                                                          │
   │  D1–2         D3–4                                       ▼
   │                                    ▸ GATE 1  code_review ────┐
   │                                                          merged
   │  D7–9                              deploying_test → testing_test
   │                                    ▸ GATE 2  cab_review (CAB / e-CAB)
   │  D10–11                            deploying_staging → testing_staging
   │                                    ▸ GATE 3  business_signoff
   │  D12–13                            deploying_production → verifying_production
   │  D14                               closed
   └────────────────► rejected · risk_accepted · rolled_back
```

Every transition writes an `audit_event`. Nothing moves stage without one.

---

## 4. GitHub integration — how Ba0Ba0 becomes the gate

Register a GitHub App, **Ba0Ba0 Patch Orchestrator**.

- **Permissions:** Actions `read` · Deployments `read/write` · Contents `read/write` · Pull requests `read/write` · Checks `read` · Environments `read/write` · Security events `read` · Dependabot alerts `read` · Metadata `read`.
- **Webhook events:** `deployment_protection_rule`, `workflow_run`, `workflow_job`, `deployment_status`, `pull_request`, `check_suite`, `code_scanning_alert`, `dependabot_alert`.
- **Auth:** App JWT → installation access token (cache; 1 h TTL). Verify every webhook with HMAC-SHA256 (`X-Hub-Signature-256`).

**Recommendation: use both gate mechanisms, not one.**

| | Native *required reviewers* | **Custom deployment protection rule** |
|---|---|---|
| Approval happens in | GitHub UI | **Ba0Ba0 UI** |
| Mechanism | GitHub blocks, waits for a listed reviewer | GitHub POSTs `deployment_protection_rule` to our webhook and waits; we reply via `POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule` with `state: approved｜rejected` |
| Value | auditors recognise it; native trail | **this is the demo** — the CAB decision in Ba0Ba0 releases a real Azure deploy |

Configure `production` with **both**: the custom rule enforces Ba0Ba0's policy (CAB approved + tests green + evidence complete), and native required reviewers provide the familiar GitHub trail. Belt and braces, and it demos beautifully.

**PR creation:** create branch → commit patch via Contents API → open PR with a body linking back to the Ba0Ba0 change. In-app code-review approval posts a real GitHub PR review.

**Getting run state back — three layers, because GitHub does not stream logs.** `GET /repos/{}/actions/jobs/{job_id}/logs` returns a 302 to a blob URL that expires in ~1 minute and is only reliable once the job has *completed*. Any design assuming live log streaming will fail.
1. `workflow_job` webhooks deliver the job's `steps[]` with per-step status and timings — push-based, near-real-time. **This is what drives the run timeline UI.**
2. A `baobao-report` composite action posts structured progress from inside the workflow, authenticated with **GitHub's own OIDC token** (audience `api://baobao`, verified against GitHub's JWKS, asserting the `repository`/`environment`/`workflow_ref` claims) — so there is **no shared secret between GitHub and Ba0Ba0 at all**.
3. On `workflow_run.completed`, pull full logs and artifact zips, hash them, store to Blob, create `evidence` rows. Download immediately — those URLs expire.

**Two gotchas that bite:**
- Pushes made with a workflow's default `GITHUB_TOKEN` **do not trigger new workflow runs** (recursion guard); pushes with a **GitHub App installation token do**. Since AI patch branches must kick off CI, Ba0Ba0 must open PRs with the App token. *This alone justifies the App over a PAT.*
- GitHub waits **up to 30 days** for a protection-rule response — comfortably longer than a 14-day cycle, so a run really can sit paused across the whole demo.

Installation rate limit is 5 000 req/h; webhooks keep us far under. The real risk is *secondary* limits (~100 concurrent, content-creating calls must be spaced) — serialize PR creation through a queue with jitter.

---

## 5. CI/CD — reusable workflows and the promotion chain

One central repo `baobao-workflows` exposing `workflow_call` workflows consumed by all four target repos:

| Workflow | Does |
|---|---|
| `scan.yml` | Trivy (fs + image + VM), CodeQL, `npm audit`/`pip-audit`, Checkov → normalise → `POST /api/ingest/scanner` |
| `build.yml` | build, push to ACR, generate SBOM (Syft) |
| `test.yml` | unit + API + Playwright UI; upload JUnit XML, traces, videos |
| `deploy.yml` | OIDC login → deploy to env → canary/slot-swap → smoke test → health check → auto-rollback on failure |

**Promotion chain:** `test` (auto on merge) → `staging` (GATE 2) → `production` (GATE 3).

**Azure auth:** OIDC federated credentials on an Entra App Registration, one per repo+environment subject. `azure/login@v2` — **no long-lived secrets in GitHub**.

**Canary & rollback:**
- *Container Apps* — `az containerapp ingress traffic set --revision-weight <rev>=10` → `=50` → `=100`; rollback shifts 100 % back to the previous revision. **Gotcha:** the app must be created in *multiple revision mode* or traffic splitting is unavailable — set this in Terraform up front, weights must total 100.
- *App Service* — deploy to staging slot, warm, `az webapp deployment slot swap`; rollback = swap back.
- Health check failure or smoke-test failure triggers rollback automatically and moves the change to `rolled_back`.

---

## 6. Test generation → real execution → evidence

This closes SOW capability (i), the biggest credibility gap.

1. `/api/test-plan` generates the plan (already works — keep it).
2. **New: materialisation.** Claude takes the plan + the actual patch diff and writes real test files onto the patch branch:
   - `tests/api/<cve>.spec.ts` — Vitest + supertest (or pytest for Python)
   - `tests/ui/<cve>.spec.ts` — Playwright, run against the deployed environment URL
   - **Then prove it.** A `verify-vulnerable` job runs the generated security test against the **pre-patch** deployment on the base commit. A recorded **red-then-green** transition is genuine evidence the patch works — and it catches the failure mode where the AI writes a test that passes trivially. This is the single strongest artifact in the whole demo.
3. CI runs unit + API + UI + security re-scan + (post-deploy) smoke tests.
4. JUnit XML, Playwright HTML reports, traces, videos and screenshots upload as artifacts; Ba0Ba0 ingests them into `test_runs` + `evidence_artifacts`.
5. The pre-existing regression suite must still pass — this is what trips scenario 8 into rollback.

---

## 7. AI architecture

**Keep Gemini** for triage, analysis, report, chat — it works, structured output via `z.toJSONSchema` is solid, and [lib/ai/fallbacks.ts](lib/ai/fallbacks.ts) gives graceful degradation. Don't churn it.

**Add Claude** for the code tasks, via a new `lib/ai/claude.ts` mirroring the `generateStructured()` contract in [lib/ai/gemini.ts](lib/ai/gemini.ts):
- `claude-opus-4-8` — patch generation
- `claude-sonnet-5` — test authoring and the cheaper iteration loop

**Run the patch agent via the Claude Agent SDK** (`@anthropic-ai/claude-agent-sdk`) in an ephemeral **Container App Job** — it gives you the Read/Write/Edit/Bash loop, permissions and hooks out of the box, and you already need somewhere to clone repos and run `npm test`. Everything stays in your tenancy.

**A deterministic strategy router sits in front of the LLM** — plain code, not a model call:

| Finding | Route |
|---|---|
| Dependency CVE with a clean semver fix · container base-image bump · OS package · IaC where Checkov offers an autofix | **mechanical — no LLM** |
| Dependency CVE that's transitive/major · SAST code vulnerability · IaC with no autofix | **Claude** |

Roughly **60 % of findings never reach the LLM.** That is simultaneously a cost control, a latency control, and the answer to *"are you just letting an AI rewrite our code?"*

**Patch loop:** context pack (CVE + advisory + the exact vulnerable file/line from the SARIF + surrounding code + repo conventions) → generate → apply on a branch → run build + existing suite + the new security regression test → on failure feed the output back, max 3–4 iterations → score confidence → open PR.

**Confidence is computed deterministically, never self-reported by the model** (tests pass · inverse diff size · files touched · no new deps · SAST rule cleared). ≥85 and small diff → PR with CODEOWNERS review; 60–85 → *draft* PR flagged for an engineer; <60 → no PR, just a work item with the analysis. **Ba0Ba0 — not the agent — pushes the branch and opens the PR.** The agent never holds a credential that can write to GitHub, and runs with no network access.

**Guardrails** (non-negotiable):
- File allowlist — only dependency manifests and the specific flagged file; never CI config, secrets, or auth code.
- Diff size cap; reject anything unexpectedly large.
- SAST code fixes **always** require human review (scenario 2) — never auto-merge a logic change.
- Confidence below threshold → escalate to a human rather than opening a PR.

---

## 8. Frontend evolution

| Current | Fate |
|---|---|
| dashboard, vulnerabilities, impact | **rewire** to real DB aggregates (`affected-servers.tsx` is already data-driven — keep as is) |
| upload | **keep** as manual scanner import; fix the silent-fallback bug in [lib/parse/index.ts](lib/parse/index.ts#L22-L29) where a failed parse quietly substitutes the whole demo dataset |
| analysis | keep the AI verdict; replace the fake `PatchRun` with the real patch run |
| cab | approvals become persisted, RBAC'd, and **gate GitHub** |
| test-plan | plan → materialised tests → live results |
| [deploy-run.tsx](components/deploy/deploy-run.tsx) | **rewrite the data source, keep the UI.** The GitHub-authentic styling is genuinely good — swap hardcoded steps for real `workflow_job` data, and fix the Cloud Run references to Azure |
| [ansible-run.tsx](components/deploy/ansible-run.tsx), [code-review.tsx](components/deploy/code-review.tsx) | **rewrite** against real playbook output / real PR diff |
| — | **NEW: Patch Lifecycle board** — one change moving Day 1→14 across gates. The repo's own docs call this the single highest-value addition, and it's what visually proves "30 → 14 days" |
| — | **NEW:** approval inbox (per-persona queue), evidence-pack viewer, login + persona switcher |

Client data access moves from the localStorage `DataProvider` to server components + a thin mutation layer; [lib/api-client.ts](lib/api-client.ts) is the clean seam to redirect.

---

## 9. Personas, RBAC and gate ownership

| Persona | In-app role | GitHub | Acts at |
|---|---|---|---|
| Security Analyst | `security_analyst` | team `sec` | triage; risk acceptance (scenario 7) |
| App Owner / Dev Lead | `app_owner` | `CODEOWNERS` | **Gate 1** — code review |
| Infra Engineer | `infra_engineer` | team `infra` | Ansible + IaC approval |
| QA Lead | `qa_lead` | — | test evidence sign-off |
| Change Manager / CAB Chair | `cab_chair` | `production` required reviewer | **Gate 2** — CAB / e-CAB |
| Business Owner | `business_owner` | `production` required reviewer | **Gate 3** — production go/no-go |
| SRE | `sre` | team `sre` | rollback authority |

e-CAB routing (SOW capability f) is automatic: severity + internet-facing + exploit-available + window < 7 days → emergency path, two approvers, standard CAB skipped.

---

## 10. Five-week plan

**Week 0 — pre-flight (2–3 days, overlappable).** De-risk the two things that could invalidate the architecture, using throwaway code: (1) prove an Actions job assumes an Azure identity via **OIDC** and runs `az containerapp update`; (2) prove a GitHub App receives a `deployment_protection_rule` webhook and approves it via the REST callback. Also: confirm the org name, decide the App Service SKU, create the Neon project and the Azure budget alert. **If both spikes work by day 2, the rest is execution. If either fails, the architecture needs rethinking now — not in Week 4.**

| Week | Deliverable | Demoable at end of week |
|---|---|---|
| **1** — Foundations | Postgres + Drizzle schema; Auth.js + Entra SSO; RBAC; hash-chained audit log; Terraform estate (RG, ACR, Container Apps, App Service, VM, PG, Key Vault, Log Analytics); GitHub App registered + webhook receiver; OIDC federation | Log in as a persona; real Azure resources exist; hello-world deploys via Actions with **no secrets** |
| **2** — Ingestion | 4 dummy repos with pinned vulnerable deps; `scan.yml`; scanner→Ba0Ba0 ingestion, normalisation, dedupe, asset correlation; dashboard/vulnerabilities/impact on real data | Scheduled scans run; **real findings** flow into the dashboard |
| **3** — AI patching | Patch strategy router (5 channels); Claude patch loop + guardrails; programmatic branch/PR; real code-review UI backed by the GitHub diff | CVE → AI patch → **real PR** → approve in Ba0Ba0 → merged |
| **4** — Execution & gates | Test materialisation; `test.yml` + `deploy.yml`; GitHub Environments + protection rules; **custom deployment protection rule end-to-end**; canary + slot swap + auto-rollback; Ansible path | Full chain **test → staging → production**, each gate released from Ba0Ba0 |
| **5** — Closure & polish | Lifecycle board; evidence pack (PDF); Teams/email notifications; cycle-time metrics; seed/reset script; rehearsal | The complete 20-minute narrative, repeatable |

**De-scope lever if Week 2 slips:** drop `baobao-batch-worker` (container scenario overlaps with payments-api). Never drop the VM/Ansible repo — it's the only IaaS story.

---

## 11. Demo narrative (~20 min)

The honest framing: **the 14 days are wall-clock time waiting on humans, not machines.** The pipeline itself takes minutes. So compressing the demo isn't cheating — we simply don't wait for humans between gates. Say this out loud to the client; it's a strength.

- **Pre-staged:** the morning's scan results (real, just run earlier), and 2–3 changes parked at different lifecycle stages so the board looks like a live operation.
- **Live in the room:** pick a critical CVE → AI generates the patch → **real PR appears on github.com** → approve as App Owner → CI runs for real (~3–4 min) → deploys to test → switch browser to CAB Chair → approve → staging → Business Owner signs off → **production canary 10→50→100 %** → smoke tests → change closed → evidence pack PDF.
- **Deliberately show scenario 8** (patch breaks a test → auto-rollback) and **scenario 7** (analyst overrides the AI and records a risk acceptance). These prove judgement and a safety net.
- Use two browser sessions to prove RBAC is real, not a role dropdown.
- State plainly which parts were pre-run.

---

## 12. Risks

| Risk | Mitigation |
|---|---|
| **App Service slots need Standard tier (~$70/mo)** — this alone eats half the $80–150 ceiling. Microsoft is explicit: slots require Standard/Premium/Isolated | **Decide in Week 0.** Recommended: run B1 in Weeks 1–2, scale to S1 for Weeks 3–5 via a Terraform variable (note: slots are destroyed on scale-down, recreated on scale-up). Alternatives: raise ceiling to ~$180/mo, or demo blue/green on Container Apps revisions only and drop the slot-swap scenario |
| **GitHub plan** — required reviewers on private repos need **Enterprise**, not Team | Verify day 1. Fallback: make the four dummy repos public (no client IP in them) |
| **Custom deployment protection rules are public preview**, and must be enabled **per-environment by a repo admin** after the App is installed — Terraform's `github_repository_environment` does not manage this | Build *and rehearse* the native-required-reviewer fallback, not just document it. Budget a manual enablement step |
| Ansible reachability to the Azure VM from GitHub runners | Public IP + NSG allowlist + Key Vault SSH key; fallback is a self-hosted runner in the VNet |
| AI patch quality on SAST fixes | Mandatory human review + test-gated iteration + confidence threshold |
| Azure cost drift | Budget alert at $150; auto-shutdown schedule on the VM; single RG for easy teardown |
| **Demo fragility** — everything real means everything can fail live | Keep a recorded run and a "replay last successful run" mode as insurance |
| 5 weeks for 4 repos + full pipeline is tight | De-scope lever above; Week 0 de-risks OIDC and the gate first. **Building deployable vulnerable repos is boring work that always overruns** — commit to 3, treat the 4th as stretch |
| Ansible reachability from GitHub runners to the VM | Ephemeral NSG rule scoped to the runner's egress IP, SSH key from Key Vault. **Fallback: `az vm run-command invoke`** — always works, needs no inbound path |
| Prompt-injection surface — the patch agent reads CVE advisories, scanner output and repo files | No network, no credentials, path allowlist, mandatory human review. Worth one slide; sophisticated clients ask |
| Entra `groups` claim must be explicitly enabled in the app registration's token configuration | Easy to miss, costs half a day. Do it in Week 1 |

**Two rules for the team:**
1. **Do not refactor anything in [lib/ai/](lib/ai/) that currently works.** Persist its output; don't replace it. SOW capabilities (a)–(g) already exist and function — the 5-week timeline is achievable *only* because of that. The moment someone starts rewriting the Gemini layer, the timeline is gone.
2. **Staffing is ~2 engineers × 5 weeks.** For 1 engineer, cut to 3 repos and 5 scenarios.

---

## Verification

- **Week 1:** `terraform apply` succeeds; a trivial workflow deploys to Azure via OIDC with zero stored secrets; login as two personas shows different permissions; an audit event's hash chain validates.
- **Week 2:** introduce a known-vulnerable dependency → scheduled scan detects it → it appears in the Ba0Ba0 dashboard within one scan cycle, correctly correlated to its asset.
- **Week 3:** trigger patch generation on a seeded CVE → confirm a real PR exists on GitHub with a sane diff → approving in Ba0Ba0 posts a real PR review.
- **Week 4 (the critical test):** start a production deploy → confirm GitHub shows the run **blocked pending Ba0Ba0's protection rule** → approve in Ba0Ba0 → confirm the deploy proceeds and the app version changes in Azure. Then force a smoke-test failure and confirm automatic rollback.
- **Week 5:** run all 8 CVE scenarios end-to-end from a clean seed; export the evidence pack and check every approval, test result and deployment log is present.
- Extend `npm run validate` ([scripts/validate-fallbacks.ts](scripts/validate-fallbacks.ts)) into a referential-integrity check against the real DB.
- Add CI for Ba0Ba0 itself — the platform should be built by the pipeline it advocates.
