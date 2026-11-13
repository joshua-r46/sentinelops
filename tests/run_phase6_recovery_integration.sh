#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/tests/lib/isolated_docker.sh"
isolated_docker_init
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$RANDOM-$RANDOM"
LABEL_KEY="agentshield.phase6.recovery.integration.run"
LABEL_VALUE="$RUN_ID"
NETWORK="phase6-recovery-it-$RUN_ID"
POSTGRES="phase6-recovery-pg-$RUN_ID"
REDIS="phase6-recovery-redis-$RUN_ID"
API="phase6-recovery-api-$RUN_ID"
API_BACKEND="phase6-recovery-api-v1-$RUN_ID"
DEPLOYER="phase6-recovery-deployer-$RUN_ID"
SNAPSHOT="phase6-recovery-snapshot-$RUN_ID"
POLICY="phase6-recovery-policy-$RUN_ID"
RUNNER="phase6-recovery-runner-$RUN_ID"
PG_PASSWORD="$(openssl rand -hex 24)"
SNAPSHOT_TOKEN="$(openssl rand -hex 32)"
OPERATOR_TOKEN="$(openssl rand -hex 32)"
APPROVER_TOKEN="$(openssl rand -hex 32)"
OPERATOR_JSON="{\"phase6-operator\":\"$OPERATOR_TOKEN\"}"
APPROVER_JSON="{\"phase6-approver\":\"$APPROVER_TOKEN\"}"
INTEGRITY_KEY_FILE="$(mktemp /dev/shm/agentshield-phase6-recovery-key.XXXXXX)"
TEST_CATALOG="$(mktemp /dev/shm/agentshield-phase6-recovery-catalog.XXXXXX)"
openssl rand -hex 32 > "$INTEGRITY_KEY_FILE"
chmod 600 "$INTEGRITY_KEY_FILE"
DATABASE_URL="postgresql://shopstack_it:$PG_PASSWORD@$POSTGRES:5432/shopstack_it"
API_IMAGE="agentshield-api-v1:phase6.3"
ROUTER_IMAGE="agentshield-api-router:phase6-recovery-it-$RUN_ID"
DEPLOYER_IMAGE="shopstack-deployer:phase6-recovery-it-$RUN_ID"
AGENT_IMAGE="agentshield:phase6-recovery-it-$RUN_ID"
NETWORK_CREATED=0

cleanup() {
  ids="$(docker ps -aq --filter "label=$LABEL_KEY=$LABEL_VALUE")"
  if [[ -n "$ids" ]]; then docker rm -fv $ids >/dev/null 2>&1 || true; fi
  if [[ "$NETWORK_CREATED" == 1 ]]; then docker network rm "$NETWORK" >/dev/null 2>&1 || true; fi
  rm -f "$INTEGRITY_KEY_FILE"
  rm -f "$TEST_CATALOG"
}
trap cleanup EXIT

for name in "$NETWORK" "$POSTGRES" "$REDIS" "$API" "$API_BACKEND" "$DEPLOYER" "$SNAPSHOT" "$POLICY" "$RUNNER"; do
  if docker container inspect "$name" >/dev/null 2>&1 || docker network inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to use an existing Docker object named $name" >&2
    exit 2
  fi
done

docker image inspect "$API_IMAGE" >/dev/null
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$ROUTER_IMAGE" -f api/router.Dockerfile api
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$DEPLOYER_IMAGE" -f deployer/Dockerfile deployer
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$AGENT_IMAGE" -f agentshield/Dockerfile agentshield
python3 - "$TEST_CATALOG" "$NETWORK" <<'PY'
import json, pathlib, sys
catalog = json.loads(pathlib.Path("deployment/catalog.json").read_text())
for item in catalog["versions"].values(): item["profile"]["network"] = sys.argv[2]
pathlib.Path(sys.argv[1]).write_text(json.dumps(catalog))
PY
chmod 0444 "$TEST_CATALOG"
docker network create --label "$LABEL_KEY=$LABEL_VALUE" "$NETWORK" >/dev/null
NETWORK_CREATED=1
docker run -d --rm --name "$POSTGRES" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=256m \
  -e POSTGRES_DB=shopstack_it -e POSTGRES_USER=shopstack_it -e POSTGRES_PASSWORD="$PG_PASSWORD" postgres:16-alpine >/dev/null
docker run -d --rm --name "$REDIS" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  redis:7-alpine redis-server --save "" --appendonly no >/dev/null
ready=0
for _ in $(seq 1 60); do
  if docker exec "$POSTGRES" pg_isready -q -U shopstack_it -d shopstack_it && docker exec "$REDIS" redis-cli ping 2>/dev/null | grep -qx PONG; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then echo "Disposable database/cache did not become ready" >&2; exit 1; fi

docker exec "$POSTGRES" psql -v ON_ERROR_STOP=1 -U shopstack_it -d shopstack_it -c "CREATE TABLE agentshield_incidents (id UUID PRIMARY KEY, state TEXT NOT NULL, status TEXT NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL); CREATE TABLE agentshield_action_requests (id UUID PRIMARY KEY, incident_id UUID NOT NULL, status TEXT NOT NULL, decision TEXT NOT NULL, action_type TEXT NOT NULL, parameters JSONB NOT NULL); CREATE TABLE agentshield_action_audit (id UUID PRIMARY KEY, action_request_id UUID, event_type TEXT NOT NULL, actor TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL); CREATE TABLE agentshield_verifications (execution_id UUID PRIMARY KEY, incident_id UUID NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL, evidence JSONB NOT NULL, evidence_sha256 TEXT NOT NULL, started_at TIMESTAMPTZ NOT NULL, completed_at TIMESTAMPTZ NOT NULL)"
docker run -d --rm --name "$API_BACKEND" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" --network-alias api-v1 \
  -e DATABASE_URL="$DATABASE_URL" -e REDIS_URL="redis://$REDIS:6379/0" "$API_IMAGE" >/dev/null
docker run -d --rm --name "$API" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" --network-alias api \
  -e ROUTER_INITIAL_VERSION=v1 -e DEPLOYMENT_CATALOG_FILE=/etc/agentshield/deployment-catalog.json \
  -v "$TEST_CATALOG:/etc/agentshield/deployment-catalog.json:ro" "$ROUTER_IMAGE" >/dev/null
docker run -d --rm --name "$DEPLOYER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" "$DEPLOYER_IMAGE" >/dev/null
docker run -d --rm --name "$SNAPSHOT" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e SNAPSHOT_TOKEN="$SNAPSHOT_TOKEN" \
  -e SNAPSHOT_INTEGRITY_KEY_FILE=/run/secrets/snapshot_integrity_key \
  -v "$INTEGRITY_KEY_FILE:/run/secrets/snapshot_integrity_key:ro" \
  -e SNAPSHOT_API_URL="http://$API:8000" -e SNAPSHOT_DEPLOYER_URL="http://$DEPLOYER:8001" \
  "$AGENT_IMAGE" uvicorn snapshots:app --host 0.0.0.0 --port 8006 >/dev/null
for _ in $(seq 1 60); do
  if docker run --rm --network "$NETWORK" "$AGENT_IMAGE" python -c "import urllib.request; urllib.request.urlopen('http://$SNAPSHOT:8006/health', timeout=2)" >/dev/null 2>&1; then break; fi
  sleep 1
done
docker run -d --rm --name "$POLICY" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e SNAPSHOT_INTEGRITY_KEY_FILE=/run/secrets/snapshot_integrity_key \
  -v "$INTEGRITY_KEY_FILE:/run/secrets/snapshot_integrity_key:ro" \
  -e RECOVERY_OPERATOR_TOKENS_JSON="$OPERATOR_JSON" -e RECOVERY_APPROVER_TOKENS_JSON="$APPROVER_JSON" \
  -e RECOVERY_MAX_SNAPSHOT_AGE_SECONDS=3600 -e RECOVERY_MAX_ATTEMPTS_PER_INCIDENT=3 \
  "$AGENT_IMAGE" uvicorn recovery_policy:app --host 0.0.0.0 --port 8007 >/dev/null

if ! docker run --rm --name "$RUNNER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e PYTHONPATH=/app -e RECOVERY_POLICY_URL="http://$POLICY:8007" -e SNAPSHOT_URL="http://$SNAPSHOT:8006" \
  -e DATABASE_URL="$DATABASE_URL" -e SNAPSHOT_TOKEN="$SNAPSHOT_TOKEN" \
  -e RECOVERY_OPERATOR_TOKEN="$OPERATOR_TOKEN" -e RECOVERY_APPROVER_TOKEN="$APPROVER_TOKEN" \
  -e SNAPSHOT_INTEGRITY_KEY_FILE=/run/secrets/snapshot_integrity_key \
  -v "$INTEGRITY_KEY_FILE:/run/secrets/snapshot_integrity_key:ro" \
  -v "$ROOT/tests/test_phase6_recovery_integration.py:/test_phase6_recovery_integration.py:ro" \
  "$AGENT_IMAGE" python /test_phase6_recovery_integration.py; then
  docker logs "$POLICY" >&2 || true
  docker logs "$SNAPSHOT" >&2 || true
  exit 1
fi
echo "Phase 6.3 recovery-policy integration passed; production execution remained disabled."
