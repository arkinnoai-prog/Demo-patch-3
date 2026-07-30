#!/usr/bin/env bash
#
# Return 100% of traffic to the previous revision and deactivate the bad one.
#
#   rollback.sh --env production
#
# This is CVE scenario 8's safety net (POC-PLAN.md §2, §5): a patch that breaks a smoke
# test never stays in front of users, and the change moves to `rolled_back` rather than
# `closed`.  Scenario 8 is one of the two the plan calls out as mattering most for
# credibility, so this script gets demoed deliberately, not just documented.

set -euo pipefail

APP_NAME="${APP_NAME:-baobao-batch-worker}"
RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-}"
ENVIRONMENT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) ENVIRONMENT="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

: "${ENVIRONMENT:?--env is required}"
: "${RESOURCE_GROUP:?AZURE_RESOURCE_GROUP must be set}"

APP="${APP_NAME}-${ENVIRONMENT}"

echo "::group::rollback ${APP}"

TARGET="${PREVIOUS_REVISION:-}"
if [[ -z "${TARGET}" ]]; then
  TARGET="$(
    az containerapp revision list --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
      --query "[?properties.active].{n:name, t:properties.createdTime} | sort_by(@, &t) | [-2].n" \
      -o tsv 2>/dev/null || true
  )"
fi

if [[ -z "${TARGET}" ]]; then
  # A first-ever deploy has nothing to roll back to.  Fail loudly — silently "succeeding"
  # here would leave a broken revision serving traffic while the workflow reports green.
  echo "::error::no previous revision to roll back to on ${APP}"
  exit 1
fi

CURRENT="$(
  az containerapp revision list --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --query "[?properties.active].{n:name, t:properties.createdTime} | sort_by(@, &t) | [-1].n" \
    -o tsv
)"

echo "shifting 100% of traffic ${CURRENT} → ${TARGET}"
az containerapp ingress traffic set \
  --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
  --revision-weight "${TARGET}=100" --output none

# Deactivate the bad revision so it cannot be reached directly and stops billing.
if [[ -n "${CURRENT}" && "${CURRENT}" != "${TARGET}" ]]; then
  az containerapp revision deactivate \
    --revision "${CURRENT}" --name "${APP}" --resource-group "${RESOURCE_GROUP}" \
    --output none || echo "warning: could not deactivate ${CURRENT}"
fi

# The batch job shares the image, so it has to come back too — otherwise the next
# scheduled run executes the rolled-back build.
if az containerapp job show --name "${APP_NAME}-job-${ENVIRONMENT}" \
     --resource-group "${RESOURCE_GROUP}" &>/dev/null; then
  PREVIOUS_IMAGE="$(
    az containerapp revision show --revision "${TARGET}" --name "${APP}" \
      --resource-group "${RESOURCE_GROUP}" \
      --query "properties.template.containers[0].image" -o tsv
  )"
  az containerapp job update \
    --name "${APP_NAME}-job-${ENVIRONMENT}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "${PREVIOUS_IMAGE}" --output none
  echo "container apps job rolled back to ${PREVIOUS_IMAGE}"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "rolled-back=true"
    echo "restored-revision=${TARGET}"
  } >> "$GITHUB_OUTPUT"
fi

echo "rollback complete — ${TARGET} is serving 100% of traffic"
echo "::endgroup::"
