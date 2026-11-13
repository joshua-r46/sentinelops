#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$RANDOM-$RANDOM"
LABEL_KEY="agentshield.phase6.integration.run"
LABEL_VALUE="$RUN_ID"
NETWORK="phase6-it-$RUN_ID"
POSTGRES="phase6-it-postgres-$RUN_ID"
REDIS="phase6-it-redis-$RUN_ID"
API="phase6-it-api-$RUN_ID"
DEPLOYER="phase6-it-deployer-$RUN_ID"
SNAPSHOT="phase6-it-snapshot-$RUN_ID"
RUNNER="phase6-it-runner-$RUN_ID"
PG_PASSWORD="$(openssl rand -hex 24)"
TOKEN="$(openssl rand -hex 32)"
INTEGRITY_KEY_FILE="$(mktemp)"
openssl rand -hex 32 > "$INTEGRITY_KEY_FILE"
chmod 600 "$INTEGRITY_KEY_FILE"
DATABASE_URL="postgresql://shopstack_it:$PG_PASSWORD@$POSTGRES:5432/shopstack_it"
API_IMAGE="shopstack-api:phase6-snapshot-it"
DEPLOYER_IMAGE="shopstack-deployer:phase6-snapshot-it"
SNAPSHOT_IMAGE="agentshield:phase6-snapshot-it"
NETWORK_CREATED=0

cleanup() {
  ids="$(docker ps -aq --filter "label=$LABEL_KEY=$LABEL_VALUE")"
  if [[ -n "$ids" ]]; then docker rm -fv $ids >/dev/null 2>&1 || true; fi
  if [[ "$NETWORK_CREATED" == 1 ]]; then docker network rm "$NETWORK" >/dev/null 2>&1 || true; fi
  rm -f "$INTEGRITY_KEY_FILE"
}
trap cleanup EXIT

for name in "$NETWORK" "$POSTGRES" "$REDIS" "$API" "$DEPLOYER" "$SNAPSHOT" "$RUNNER"; do
  if docker container inspect "$name" >/dev/null 2>&1 || docker network inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to use an existing Docker object named $name" >&2
    exit 2
  fi
done

docker build -t "$API_IMAGE" -f api/Dockerfile api
docker build -t "$DEPLOYER_IMAGE" -f deployer/Dockerfile deployer
docker build -t "$SNAPSHOT_IMAGE" -f agentshield/Dockerfile agentshield
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

docker exec "$POSTGRES" psql -v ON_ERROR_STOP=1 -U shopstack_it -d shopstack_it -c "CREATE TABLE agentshield_incidents (id UUID PRIMARY KEY, state TEXT NOT NULL, status TEXT NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL); CREATE TABLE agentshield_action_requests (id UUID PRIMARY KEY, incident_id UUID NOT NULL, status TEXT NOT NULL, decision TEXT NOT NULL, action_type TEXT NOT NULL, parameters JSONB NOT NULL); CREATE TABLE agentshield_action_audit (id UUID PRIMARY KEY, action_request_id UUID, event_type TEXT NOT NULL, actor TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)"
docker run -d --rm --name "$API" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e REDIS_URL="redis://$REDIS:6379/0" "$API_IMAGE" >/dev/null
docker run -d --rm --name "$DEPLOYER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" "$DEPLOYER_IMAGE" >/dev/null
docker run -d --rm --name "$SNAPSHOT" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e SNAPSHOT_TOKEN="$TOKEN" \
  -e SNAPSHOT_INTEGRITY_KEY_FILE=/run/secrets/snapshot_integrity_key \
  -v "$INTEGRITY_KEY_FILE:/run/secrets/snapshot_integrity_key:ro" \
  -e SNAPSHOT_API_URL="http://$API:8000" -e SNAPSHOT_DEPLOYER_URL="http://$DEPLOYER:8001" \
  "$SNAPSHOT_IMAGE" uvicorn snapshots:app --host 0.0.0.0 --port 8006 >/dev/null
if ! docker run --rm --name "$RUNNER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e SNAPSHOT_URL="http://$SNAPSHOT:8006" -e SNAPSHOT_TOKEN="$TOKEN" -e DATABASE_URL="$DATABASE_URL" \
  -e API_URL="http://$API:8000" -e DEPLOYER_URL="http://$DEPLOYER:8001" \
  -v "$ROOT/tests/test_phase6_snapshot_integration.py:/test_phase6_snapshot_integration.py:ro" \
  "$SNAPSHOT_IMAGE" python /test_phase6_snapshot_integration.py; then
  docker logs "$SNAPSHOT" >&2 || true
  exit 1
fi
echo "Phase 6.1 disposable snapshot integration passed; only temporary labeled containers and tmpfs database were used."
