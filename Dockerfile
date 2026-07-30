# syntax=docker/dockerfile:1
#
# ---- frontend build stage --------------------------------------------------
# Builds the React (Vite) SPA.  This stage is thrown away — only the static bundle is
# copied into the runtime image below — so Node never ships in the deployed image and
# the Trivy image scan still sees the seeded old Debian base, nothing else.
FROM node:20-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- runtime image ---------------------------------------------------------
#
# baobao-batch-worker
#
# ⚠️  DELIBERATELY VULNERABLE BASE IMAGE — Ba0Ba0 CVE scenario 3 (POC-PLAN.md §2).
#
#     python:3.11.4-slim-bookworm is the June 2023 build.  A Trivy image scan of the
#     Debian layer reports CRITICALs (zlib CVE-2023-45853, libwebp CVE-2023-4863) plus
#     glibc / perl / openssl HIGHs.
#
#     Expected remediation channel: MECHANICAL base-image bump (no LLM).  Ba0Ba0 opens a
#     PR rewriting the FROM line below; verification is an image re-scan asserting
#     CRITICAL == 0.  The patch target is recorded in .baobao/patch-targets.md.
#
#     In production this line should be digest-pinned.  It is tag-pinned here so the
#     seeded state is readable in a diff during the demo.
FROM python:3.11.4-slim-bookworm AS base

LABEL org.opencontainers.image.title="baobao-batch-worker" \
      org.opencontainers.image.description="Scanner-report ingestion batch worker (Ba0Ba0 POC target)" \
      org.opencontainers.image.source="https://github.com/BAOBAO_ORG/baobao-batch-worker" \
      io.baobao.role="patch-target" \
      io.baobao.scenario="3"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    APP_HOME=/app \
    WORKER_DATA_DIR=/var/lib/baobao

WORKDIR ${APP_HOME}

# curl is needed by the Container Apps health probe and by scripts/smoke.py fallbacks.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# uv installs the runtime dependencies — same tool, same requirements.txt and same exact
# pins as local development and CI, so "works on my machine" and "works in the image"
# mean the same thing.  `--system` targets the image's interpreter directly; there is no
# virtualenv inside a container that only ever runs one application.
COPY --from=ghcr.io/astral-sh/uv:0.9.7 /uv /usr/local/bin/uv

COPY requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt

COPY app/ ./app/
COPY samples/ ./samples/
COPY scripts/ ./scripts/
COPY .baobao/ ./.baobao/

# The built React UI from the frontend stage.  app/main.py serves it at `/` (WEBUI_DIR
# defaults to ./frontend/dist), so one container answers both the API and the UI on 8080.
COPY --from=frontend /build/dist ./frontend/dist

# Run unprivileged.  The image is a patch target, not a vulnerability grab-bag — the
# seeded issues are the base image and the pip pins, and nothing else.
RUN useradd --create-home --uid 10001 worker \
 && mkdir -p ${WORKER_DATA_DIR} \
 && chown -R worker:worker ${APP_HOME} ${WORKER_DATA_DIR}
USER worker

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

# Default command: long-lived API mode.  Used by the `deploy.yml` smoke test and as the
# health/readiness surface.
#
# The Azure Container Apps JOB overrides this with the batch entrypoint:
#     args: ["python", "-m", "app.cli", "run", "--manifest", "samples/job-manifest.yaml"]
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "120", \
     "--access-logfile", "-", "app.main:create_app()"]
