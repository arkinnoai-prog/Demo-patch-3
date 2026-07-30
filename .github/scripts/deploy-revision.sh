#!/usr/bin/env bash
#
# Create a new Azure Container App revision for one environment and give it a traffic
# weight.  Called by deploy.yml after `azure/login@v2` has established an OIDC session.
#
#   deploy-revision.sh --env production --tag sha-a1b2c3d --weight 10
#
# Writes `url` and `revision` to $GITHUB_OUTPUT for the smoke test and rollback steps.
#
# Environment topology (POC-PLAN.md §1, "lean"): one resource group; test / staging /
# production are revisions of a single Container App, not three separate estates.  The
# app must be in MULTIPLE REVISION MODE for weights to be settable at all.

set -euo pipefail

APP_NAME="${APP_NAME:-baobao-batch-worker}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-}"
ENVIRONMENT=""
TAG=""
WEIGHT="100"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)    ENVIRONMENT="$2"; shift 2 ;;
    --tag)    TAG="$2";         shift 2 ;;
    --weight) WEIGHT="$2";      shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

: "${ENVIRONMENT:?--env is required (test|staging|production)}"
: "${TAG:?--tag is required}"
: "${RESOURCE_GROUP:?AZURE_RESOURCE_GROUP must be set}"
: "${ACR_NAME:?ACR_NAME must be set}"

APP="${APP_NAME}-${ENVIRONMENT}"
IMAGE="${ACR_NAME}.azurecr.io/${APP_NAME}:${TAG}"
REVISION_SUFFIX="${TAG//[^a-z0-9]/}"

echo "::group::deploy ${IMAGE} → ${APP} (weight ${WEIGHT}%)"

PREVIOUS_REVISION="$(
  az containerapp revision list \
    --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --query "[?properties.active].{n:name, t:properties.createdTime} | sort_by(@, &t) | [-1].n" \
    -o tsv 2>/dev/null || true
)"
echo "previous active revision: ${PREVIOUS_REVISION:-<none>}"

# Recorded so rollback.sh knows where to shift traffic back to without having to guess.
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "PREVIOUS_REVISION=${PREVIOUS_REVISION}" >> "$GITHUB_ENV"
fi

az containerapp update \
  --name "${APP}" \
  --resource-group "${RESOURCE_GROUP}" \
  --image "${IMAGE}" \
  --revision-suffix "${REVISION_SUFFIX}" \
  --set-env-vars \
      "APP_ENV=${ENVIRONMENT}" \
      "IMAGE_TAG=${TAG}" \
      "DATABASE_URL=secretref:database-url" \
      "BAOBAO_INGEST_URL=${BAOBAO_INGEST_URL:-}" \
  --output none

NEW_REVISION="$(
  az containerapp revision list \
    --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --query "[?contains(name, '${REVISION_SUFFIX}')].name | [0]" -o tsv
)"
echo "new revision: ${NEW_REVISION}"

# The Container Apps JOB shares the image with the long-lived app.  Updating it here
# keeps the scheduled batch run and the API surface on the same build — otherwise a
# rollback of one silently leaves the other on the bad image.
if az containerapp job show --name "${APP_NAME}-job-${ENVIRONMENT}" \
     --resource-group "${RESOURCE_GROUP}" &>/dev/null; then
  az containerapp job update \
    --name "${APP_NAME}-job-${ENVIRONMENT}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "${IMAGE}" \
    --output none
  echo "container apps job updated to ${TAG}"
fi

if [[ "${WEIGHT}" == "100" ]]; then
  az containerapp ingress traffic set \
    --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --revision-weight "${NEW_REVISION}=100" --output none
else
  REMAINDER=$((100 - WEIGHT))
  if [[ -n "${PREVIOUS_REVISION}" ]]; then
    # Weights must total exactly 100 or the CLI rejects the call.
    az containerapp ingress traffic set \
      --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
      --revision-weight "${NEW_REVISION}=${WEIGHT}" "${PREVIOUS_REVISION}=${REMAINDER}" \
      --output none
  else
    echo "no previous revision to hold ${REMAINDER}% — sending 100% to the new revision"
    az containerapp ingress traffic set \
      --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
      --revision-weight "${NEW_REVISION}=100" --output none
  fi
fi

FQDN="$(
  az containerapp show --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --query "properties.configuration.ingress.fqdn" -o tsv
)"
URL="https://${FQDN}"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "url=${URL}"
    echo "revision=${NEW_REVISION}"
    echo "previous=${PREVIOUS_REVISION}"
  } >> "$GITHUB_OUTPUT"
fi

echo "deployed ${TAG} to ${ENVIRONMENT} at ${URL} (${WEIGHT}% traffic)"
echo "::endgroup::"
