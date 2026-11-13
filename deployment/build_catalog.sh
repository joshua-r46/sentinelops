#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p deployment
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$RANDOM-$RANDOM"
if [[ -e deployment/catalog.json ]]; then
  echo "Refusing to replace the read-only deployment catalog; create a reviewed new catalog revision separately." >&2
  exit 2
fi
LABEL_KEY=agentshield.phase6.3.build
IMAGES=(agentshield-api-v1 agentshield-api-v2 agentshield-api-v2-bad)
CONTEXTS=(api-versions/v1 api-versions/v2 api-versions/v2-bad)
ALIASES=(agentshield-api-v1:phase6.3 agentshield-api-v2:phase6.3 agentshield-api-v2-bad:phase6.3)
for alias in "${ALIASES[@]}"; do
  if docker image inspect "$alias" >/dev/null 2>&1; then
    echo "Refusing to overwrite existing local deployment image tag: $alias" >&2
    exit 2
  fi
done
for i in "${!IMAGES[@]}"; do
  tag="${IMAGES[$i]}:phase6.3-$RUN_ID"
  docker build --label "$LABEL_KEY=$RUN_ID" -t "$tag" -f "${CONTEXTS[$i]}/Dockerfile" "${CONTEXTS[$i]}"
  docker image inspect --format '{{.Id}}' "$tag" >> "deployment/.image-ids.$RUN_ID"
  docker image tag "$tag" "${ALIASES[$i]}"
done
python3 tools/write_deployment_catalog.py "deployment/.image-ids.$RUN_ID" "$RUN_ID"
rm -f "deployment/.image-ids.$RUN_ID"
chmod 0444 deployment/catalog.json
printf 'Wrote read-only deployment/catalog.json for build %s\n' "$RUN_ID"
