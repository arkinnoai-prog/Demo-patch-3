#!/usr/bin/env bash
#
# Shift canary traffic between the latest revision and the one before it.
#
#   set-weight.sh --env production --weight 50
#
# Weights must total exactly 100 — the CLI rejects anything else, which is the most
# common way a hand-written canary step fails.

set -euo pipefail

APP_NAME="${APP_NAME:-baobao-batch-worker}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-}"
ENVIRONMENT=""
WEIGHT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)    ENVIRONMENT="$2"; shift 2 ;;
    --weight) WEIGHT="$2";      shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

: "${ENVIRONMENT:?--env is required}"
: "${WEIGHT:?--weight is required}"
: "${RESOURCE_GROUP:?AZURE_RESOURCE_GROUP must be set}"

APP="${APP_NAME}-${ENVIRONMENT}"

LATEST="$(
  az containerapp revision list --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --query "[?properties.active].{n:name, t:properties.createdTime} | sort_by(@, &t) | [-1].n" \
    -o tsv
)"
PREVIOUS="${PREVIOUS_REVISION:-$(
  az containerapp revision list --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --query "[?properties.active].{n:name, t:properties.createdTime} | sort_by(@, &t) | [-2].n" \
    -o tsv 2>/dev/null || true
)}"

if [[ "${WEIGHT}" == "100" || -z "${PREVIOUS}" || "${PREVIOUS}" == "${LATEST}" ]]; then
  az containerapp ingress traffic set \
    --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --revision-weight "${LATEST}=100" --output none
  echo "traffic: ${LATEST}=100%"
else
  REMAINDER=$((100 - WEIGHT))
  az containerapp ingress traffic set \
    --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --revision-weight "${LATEST}=${WEIGHT}" "${PREVIOUS}=${REMAINDER}" --output none
  echo "traffic: ${LATEST}=${WEIGHT}%  ${PREVIOUS}=${REMAINDER}%"
fi
