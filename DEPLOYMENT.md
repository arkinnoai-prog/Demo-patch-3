# Deployment

This repo deploys as **one container** (React UI + Flask API on port 8080) to **Azure
Container Apps**, backed by a shared **PostgreSQL Flexible Server**, in **Azure Southeast
Asia (Singapore)**.

The vulnerabilities in this app are **intentional**. GitHub does not scan them — the
client's own tool scans the **deployed** app at its public URL and reports findings to their
system. GitHub Actions here does exactly one thing: **build and deploy on a tag.**

```
git tag v1.0.0 && git push origin v1.0.0
        │
        ▼
GitHub Actions ── build image (React+Flask) ──► push to GHCR ──► az containerapp update ──► live URL
```

---

## Architecture

| Piece | What | Cost |
|---|---|---|
| Resource group | `rg-baobao-demos-sea` in `southeastasia` (Singapore) | — |
| Container Apps environment | shared by all demo apps, scale-to-zero | ~$0 idle |
| Container App (per demo) | 0.25 vCPU / 0.5 GB, external HTTPS on 8080 | ~$0 idle |
| PostgreSQL Flexible Server | Burstable **B1ms**, 32 GB, v16, shared | ~$13–16/mo |
| Log Analytics | required by the environment | ~$0–2/mo |
| Image registry | **GHCR** (ghcr.io), free | $0 |

One resource group holds **this demo plus the two other demo repos** — they share the
environment and the Postgres server (each gets its own database). **Total ≈ $15–25/mo**, and
the Postgres server can be **stopped** between demos to cut it further.

Files:
- `infra/main.bicep` — subscription-scoped; creates the RG and everything in it.
- `infra/resources.bicep` — the shared infra + one Container App per demo.
- `infra/main.bicepparam` — parameters (region, app list, Postgres creds).
- `.github/workflows/deploy.yml` — the tag → build → deploy pipeline.

---

## One-time setup (needs Azure credentials)

### 1. Provision the estate

```bash
az login                                   # or: az login --service-principal ...
az account set --subscription "<SUBSCRIPTION_ID>"

# Postgres admin password — never commit it; the param file reads it from the environment.
export PG_ADMIN_PASSWORD='<a strong password>'          # PowerShell: $env:PG_ADMIN_PASSWORD='...'

az deployment sub create \
  --name baobao-estate \
  --location southeastasia \
  --template-file infra/main.bicep \
  --parameters infra/main.bicepparam
```

This creates the resource group in Singapore, the shared environment + Postgres, and the
`demo-patch-3` Container App (on a placeholder image until the first deploy). The output
`appFqdns` lists each app's public hostname.

### 2. Wire GitHub → Azure (OIDC, no stored secrets)

Create an Entra app registration with a **federated credential** scoped to this repo, and
give it **Contributor** on the resource group:

```bash
appId=$(az ad app create --display-name "gh-demo-patch-3" --query appId -o tsv)
az ad sp create --id "$appId"

# Trust GitHub Actions from this repo (tag pushes + manual runs use the branch/tag subject).
az ad app federated-credential create --id "$appId" --parameters '{
  "name": "demo-patch-3-main",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:arkinnoai-prog/Demo-patch-3:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'

subId=$(az account show --query id -o tsv)
tenantId=$(az account show --query tenantId -o tsv)
az role assignment create --assignee "$appId" --role Contributor \
  --scope "/subscriptions/$subId/resourceGroups/rg-baobao-demos-sea"

echo "AZURE_CLIENT_ID=$appId  AZURE_TENANT_ID=$tenantId  AZURE_SUBSCRIPTION_ID=$subId"
```

> Deploys are triggered by **tags** (`v*`). Add a second federated credential with subject
> `repo:arkinnoai-prog/Demo-patch-3:ref:refs/tags/v*`, **or** simpler — set the subject to
> `repo:arkinnoai-prog/Demo-patch-3:environment:production` and add `environment: production`
> to the deploy job. The main-branch credential above also covers `workflow_dispatch` runs.

Then set these as repository **Variables** (Settings → Secrets and variables → Actions →
Variables — *not* Secrets; they are non-sensitive):

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | the `appId` above |
| `AZURE_TENANT_ID` | the tenant id |
| `AZURE_SUBSCRIPTION_ID` | the subscription id |
| `AZURE_RESOURCE_GROUP` | `rg-baobao-demos-sea` |
| `CONTAINERAPP_NAME` | `demo-patch-3` |

### 3. Make the image pullable

After the first deploy pushes an image, set the GHCR package visibility to **public** so
Container Apps can pull it with no credential:
GitHub → your profile/org → **Packages** → `demo-patch-3` → Package settings → **Change
visibility → Public**. (Prefer private? See the note at the bottom.)

### 4. Quiet GitHub's own scanning (optional but recommended)

The seeded vulnerabilities should be found by the **client's tool**, not flagged by GitHub.
In **Settings → Advanced Security / Code security**, turn **off**: Dependabot alerts,
Dependabot security updates, CodeQL/code scanning, and secret-scanning alerts.

---

## Deploying

```bash
git tag v1.0.0
git push origin v1.0.0
```

The `deploy` workflow builds the image, pushes it to GHCR, points the Container App at it,
and health-checks `/healthz`. Or run it manually: **Actions → deploy → Run workflow** (an
optional tag input). Typical run: a few minutes.

Verify:
- `https://<app-fqdn>/` serves the React dashboard.
- `https://<app-fqdn>/healthz` returns `{"status":"ok", ...}` with the deployed `image_tag`.
- `https://<app-fqdn>/api/findings` responds — the client's scanner can now hit the live app.

---

## Adding the other two demo repos

They share this resource group, environment, and Postgres server. In
`infra/main.bicepparam`, uncomment the extra entries (each gets its own database):

```bicep
param apps = [
  { name: 'demo-patch-3', db: 'baobao' }
  { name: 'demo-patch-1', db: 'paymentsdb' }
  { name: 'demo-patch-2', db: 'portaldb' }
]
```

Re-run the `az deployment sub create` command to create their Container Apps + databases.
Each repo then gets its own copy of `.github/workflows/deploy.yml` with its own
`CONTAINERAPP_NAME` variable, and deploys independently by tagging.

---

## Teardown

```bash
az group delete --name rg-baobao-demos-sea --yes --no-wait
```

Removes everything. To just pause cost, stop the Postgres server:
`az postgres flexible-server stop --name psql-baobao --resource-group rg-baobao-demos-sea`.

---

## Notes

- **Private images instead of public GHCR:** add a registry credential to the Container App
  (a GitHub PAT with `read:packages`) via `az containerapp registry set --server ghcr.io
  --username <user> --password <pat>`, and skip step 3.
- **Always-warm apps:** set `minReplicas = 1` in `infra/main.bicepparam` (small extra cost,
  no cold-start on the first request).
- **Local run** (no Azure): `docker compose up --build` — the app on `http://localhost:8080`,
  Postgres alongside it. See the README.
