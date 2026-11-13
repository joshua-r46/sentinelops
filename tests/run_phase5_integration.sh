#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/tests/lib/isolated_docker.sh"
isolated_docker_init
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$RANDOM-$RANDOM"
LABEL_KEY="agentshield.phase5.integration.run"
NETWORK="phase5-it-$RUN_ID"
POSTGRES="phase5-it-postgres-$RUN_ID"
REDIS="phase5-it-redis-$RUN_ID"
API="phase5-it-api-$RUN_ID"
WORKER="phase5-it-worker-$RUN_ID"
VERIFIER="phase5-it-verifier-$RUN_ID"
RUNNER="phase5-it-runner-$RUN_ID"
LABEL_VALUE="$RUN_ID"
PG_PASSWORD="$(openssl rand -hex 24)"
TOKEN="$(openssl rand -hex 32)"
DATABASE_URL="postgresql://shopstack_it:$PG_PASSWORD@$POSTGRES:5432/shopstack_it"
API_IMAGE="shopstack-api:phase5-it-$RUN_ID"
WORKER_IMAGE="shopstack-worker:phase5-it-$RUN_ID"
VERIFIER_IMAGE="agentshield:phase5-it-$RUN_ID"
PRIMARY_CREATED=0

cleanup() {
  ids="$(docker ps -aq --filter "label=$LABEL_KEY=$LABEL_VALUE")"
  if [[ -n "$ids" ]]; then docker rm -fv $ids >/dev/null 2>&1 || true; fi
  if [[ "$PRIMARY_CREATED" == 1 ]]; then docker network rm "$NETWORK" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

for name in "$NETWORK" "$POSTGRES" "$REDIS" "$API" "$WORKER" "$VERIFIER" "$RUNNER"; do
  if docker container inspect "$name" >/dev/null 2>&1 || docker network inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to use an existing Docker object named $name" >&2
    exit 2
  fi
done

docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$API_IMAGE" -f api/Dockerfile api
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$WORKER_IMAGE" -f worker/Dockerfile worker
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$VERIFIER_IMAGE" -f agentshield/Dockerfile agentshield
docker network create --label "$LABEL_KEY=$LABEL_VALUE" "$NETWORK" >/dev/null
PRIMARY_CREATED=1
docker run -d --rm --name "$POSTGRES" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=256m \
  -e POSTGRES_DB=shopstack_it -e POSTGRES_USER=shopstack_it -e POSTGRES_PASSWORD="$PG_PASSWORD" postgres:16-alpine >/dev/null
docker run -d --rm --name "$REDIS" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" redis:7-alpine redis-server --save "" --appendonly no >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$POSTGRES" pg_isready -q -U shopstack_it -d shopstack_it && docker exec "$REDIS" redis-cli ping 2>/dev/null | grep -qx PONG; then break; fi
  sleep 1
done
docker exec "$POSTGRES" psql -v ON_ERROR_STOP=1 -U shopstack_it -d shopstack_it -c "CREATE TABLE agentshield_incidents (id UUID PRIMARY KEY, state TEXT NOT NULL, status TEXT NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL); CREATE TABLE agentshield_evidence (id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id), source TEXT NOT NULL, kind TEXT NOT NULL, redacted_content JSONB NOT NULL, content_sha256 TEXT NOT NULL, duplicate_of UUID, collected_at TIMESTAMPTZ NOT NULL); CREATE TABLE agentshield_incident_transitions (id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id), from_state TEXT, to_state TEXT NOT NULL, reason TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL); CREATE TABLE agentshield_action_audit (id UUID PRIMARY KEY, action_request_id UUID, event_type TEXT NOT NULL, actor TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)"
docker run -d --rm --name "$API" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e REDIS_URL="redis://$REDIS:6379/0" "$API_IMAGE" >/dev/null
docker run -d --rm --name "$WORKER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e REDIS_URL="redis://$REDIS:6379/0" "$WORKER_IMAGE" >/dev/null
docker run -d --rm --name "$VERIFIER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e VERIFIER_TOKEN="$TOKEN" -e VERIFIER_API_URL="http://$API:8000" \
  -e VERIFIER_WORKER_URL="http://$WORKER:8004" -e VERIFIER_PROBE_INTERVAL=0.05 "$VERIFIER_IMAGE" \
  uvicorn verifier:app --host 0.0.0.0 --port 8005 >/dev/null

docker run --rm --name "$RUNNER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e VERIFIER_URL="http://$VERIFIER:8005" -e VERIFIER_TOKEN="$TOKEN" -e DATABASE_URL="$DATABASE_URL" \
  -e API_URL="http://$API:8000" -e WORKER_URL="http://$WORKER:8004" \
  -v "$ROOT/tests/test_phase5_disposable.py:/test_phase5_disposable.py:ro" "$VERIFIER_IMAGE" \
  python /test_phase5_disposable.py
echo "Phase 5 disposable verifier integration passed; only temporary labeled containers and tmpfs database were used."
