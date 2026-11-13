#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/tests/lib/isolated_docker.sh"
isolated_docker_init
RUN_ID="$(date -u +%Y%m%d%H%M%S)-$RANDOM-$RANDOM"
NESTED_NAME="agentshield-63-dockerd-$RUN_ID"
NESTED_NETWORK="agentshield-63-bootstrap-$RUN_ID"
LABEL_KEY="agentshield.phase6.3.integration.run"
LABEL_VALUE="$RUN_ID"
NETWORK="agentshield-63-it-$RUN_ID"
POSTGRES="as63-pg-$RUN_ID"
REDIS="as63-redis-$RUN_ID"
API_V1="as63-v1-$RUN_ID"
API_V2="as63-v2-$RUN_ID"
API_BAD="as63-bad-$RUN_ID"
ROUTER="as63-router-$RUN_ID"
PROXY="as63-proxy-$RUN_ID"
RUNNER="as63-runner-$RUN_ID"
ROUTER_IMAGE="agentshield-api-router:phase6.3-it-$RUN_ID"
PROXY_IMAGE="agentshield:phase6.3-proxy-it-$RUN_ID"
PG_PASSWORD="$(openssl rand -hex 24)"
PROXY_TOKEN="$(openssl rand -hex 32)"
ROUTER_SECRET="$(openssl rand -hex 32)"
PG_USER="agentshield_it"
PG_DB="agentshield_it"
DATABASE_URL="postgresql://$PG_USER:$PG_PASSWORD@$POSTGRES:5432/$PG_DB"
REDIS_URL="redis://$REDIS:6379/0"
TEST_CATALOG="$(mktemp /dev/shm/agentshield-phase6-3-catalog.XXXXXX)"
NESTED_STARTED=0
NESTED_PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
NESTED_DOCKER=(docker --host "tcp://127.0.0.1:$NESTED_PORT")
NESTED_CONTEXT="agentshield-63-$RUN_ID"

cleanup() {
  if [[ "$NESTED_STARTED" == 1 ]]; then
    "${NESTED_DOCKER[@]}" ps -aq --filter "label=$LABEL_KEY=$LABEL_VALUE" | xargs -r "${NESTED_DOCKER[@]}" rm -f >/dev/null 2>&1 || true
    "${NESTED_DOCKER[@]}" network rm "$NETWORK" >/dev/null 2>&1 || true
    "${NESTED_DOCKER[@]}" image rm "$ROUTER_IMAGE" "$PROXY_IMAGE" >/dev/null 2>&1 || true
  fi
  if [[ "$NESTED_STARTED" == 1 ]]; then
    docker rm -f "$NESTED_NAME" >/dev/null 2>&1 || true
    docker network rm "$NESTED_NETWORK" >/dev/null 2>&1 || true
  fi
  rm -f "$TEST_CATALOG"
}
trap cleanup EXIT

for name in "$NESTED_NAME" "$NESTED_NETWORK"; do
  if docker container inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to use existing Docker container $name" >&2
    exit 2
  fi
  if docker network inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to use existing Docker network $name" >&2
    exit 2
  fi
done
if ! docker image inspect docker:27-dind >/dev/null 2>&1; then
  echo "Required isolated-daemon image docker:27-dind is not cached; refusing a shared-engine fallback" >&2
  exit 3
fi

docker network create --label "$LABEL_KEY=$LABEL_VALUE" "$NESTED_NETWORK" >/dev/null
docker run -d --name "$NESTED_NAME" --label "$LABEL_KEY=$LABEL_VALUE" --privileged \
  --network "$NESTED_NETWORK" -p "127.0.0.1:$NESTED_PORT:2375" \
  --tmpfs /var/lib/docker:rw,noexec,nosuid,size=1g docker:27-dind \
  --host=tcp://0.0.0.0:2375 --tls=false >/dev/null
NESTED_STARTED=1
ready=0
for _ in $(seq 1 90); do
  if "${NESTED_DOCKER[@]}" info >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then echo "Nested isolated Docker daemon failed readiness" >&2; exit 1; fi
"${NESTED_DOCKER[@]}" image load < <(docker image save agentshield-api-v1:phase6.3 agentshield-api-v2:phase6.3 agentshield-api-v2-bad:phase6.3)
"${NESTED_DOCKER[@]}" pull postgres:16-alpine >/dev/null
"${NESTED_DOCKER[@]}" pull redis:7-alpine >/dev/null
"${NESTED_DOCKER[@]}" pull python:3.12-slim >/dev/null
"${NESTED_DOCKER[@]}" build --label "$LABEL_KEY=$LABEL_VALUE" -t "$ROUTER_IMAGE" -f api/router.Dockerfile api
"${NESTED_DOCKER[@]}" build --label "$LABEL_KEY=$LABEL_VALUE" -t "$PROXY_IMAGE" -f executor/Dockerfile.phase6.3-proxy executor
python3 - "$TEST_CATALOG" "$NETWORK" <<'PY'
import json, pathlib, sys
catalog = json.loads(pathlib.Path("deployment/catalog.json").read_text())
for item in catalog["versions"].values():
    item["profile"]["network"] = sys.argv[2]
pathlib.Path(sys.argv[1]).write_text(json.dumps(catalog))
PY
chmod 0444 "$TEST_CATALOG"

"${NESTED_DOCKER[@]}" network create --label "$LABEL_KEY=$LABEL_VALUE" "$NETWORK" >/dev/null
NETWORK_CREATED=1
"${NESTED_DOCKER[@]}" run -d --rm --name "$POSTGRES" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  --network-alias "$POSTGRES" --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=256m \
  -e POSTGRES_DB="$PG_DB" -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" postgres:16-alpine >/dev/null
"${NESTED_DOCKER[@]}" run -d --rm --name "$REDIS" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  --network-alias "$REDIS" redis:7-alpine redis-server --save "" --appendonly no >/dev/null

ready=0
for _ in $(seq 1 60); do
  if "${NESTED_DOCKER[@]}" exec "$POSTGRES" pg_isready -q -U "$PG_USER" -d "$PG_DB" && "${NESTED_DOCKER[@]}" exec "$REDIS" redis-cli ping 2>/dev/null | grep -qx PONG; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then echo "Disposable database/cache failed readiness" >&2; exit 1; fi

for spec in "$API_V1|agentshield-api-v1:phase6.3|api-v1" "$API_V2|agentshield-api-v2:phase6.3|api-v2" "$API_BAD|agentshield-api-v2-bad:phase6.3|api-v2-bad"; do
  IFS='|' read -r name image alias <<< "$spec"
  "${NESTED_DOCKER[@]}" run -d --rm --name "$name" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" --network-alias "$alias" \
    -e DATABASE_URL="$DATABASE_URL" -e REDIS_URL="$REDIS_URL" -e FAILURE_INJECTOR_TOKEN= "$image" >/dev/null
done

"${NESTED_DOCKER[@]}" run -d --rm --name "$ROUTER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" --network-alias api \
  -e ROUTER_CONTROL_SECRET="$ROUTER_SECRET" -e ROUTER_INITIAL_VERSION=v1 \
  -e DEPLOYMENT_CATALOG_FILE=/etc/agentshield/deployment-catalog.json \
  -e ROUTER_STATE_FILE=/var/lib/agentshield/router-state.json --tmpfs /var/lib/agentshield:rw,noexec,nosuid,size=1m \
  -v "$TEST_CATALOG:/etc/agentshield/deployment-catalog.json:ro" \
  "$ROUTER_IMAGE" >/dev/null
"${NESTED_DOCKER[@]}" run -d --rm --name "$PROXY" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e DEPLOYMENT_ENABLED=true -e DEPLOYMENT_CATALOG_FILE=/etc/agentshield/deployment-catalog.json -e DEPLOYMENT_NETWORK="$NETWORK" \
  -e API_DATABASE_URL="$DATABASE_URL" -e API_REDIS_URL="$REDIS_URL" -e ROUTER_URL=http://api:8000 \
  -e ROUTER_CONTROL_SECRET="$ROUTER_SECRET" -e PROXY_AUTH_TOKEN="$PROXY_TOKEN" \
  -e DEPLOYMENT_RUN_LABEL_KEY="$LABEL_KEY" -e DEPLOYMENT_RUN_LABEL_VALUE="$LABEL_VALUE" \
  -e DEPLOYMENT_RESOURCE_LABEL_KEY="$LABEL_KEY" -e DEPLOYMENT_RESOURCE_LABEL_VALUE="$LABEL_VALUE" \
  -e DOCKER_HOST="tcp://$NESTED_NAME:2375" -v "$TEST_CATALOG:/etc/agentshield/deployment-catalog.json:ro" \
  "$PROXY_IMAGE" >/dev/null

ready=0
for _ in $(seq 1 60); do
  if "${NESTED_DOCKER[@]}" run --rm --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" python:3.12-slim python -c \
    "import urllib.request; urllib.request.urlopen('http://api:8000/health',timeout=2)" >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then "${NESTED_DOCKER[@]}" logs "$ROUTER" >&2 || true; echo "Disposable router failed readiness" >&2; exit 1; fi

"${NESTED_DOCKER[@]}" run --rm --name "$RUNNER" --label "$LABEL_KEY=$LABEL_VALUE" --network "$NETWORK" \
  -e API_BASE=http://api:8000 -e PROXY_BASE=http://docker-proxy:2375 -e PROXY_TOKEN="$PROXY_TOKEN" \
  -e CATALOG_FILE=/etc/agentshield/deployment-catalog.json \
  -v "$TEST_CATALOG:/etc/agentshield/deployment-catalog.json:ro" \
  -v "$ROOT/tests/phase6_3_disposable.py:/phase6_3_disposable.py:ro" \
  python:3.12-slim python /phase6_3_disposable.py

for incumbent in "$API_V1" "$API_V2" "$API_BAD"; do
  running="$("${NESTED_DOCKER[@]}" inspect --format '{{.State.Running}}' "$incumbent")"
  [[ "$running" == true ]] || { echo "Incumbent $incumbent was not retained" >&2; exit 1; }
done
candidate_ids="$("${NESTED_DOCKER[@]}" ps -aq --filter "label=$LABEL_KEY=$LABEL_VALUE" --filter 'label=agentshield.managed=phase6.3')"
[[ "$(wc -w <<< "$candidate_ids")" -ge 3 ]] || { echo "Expected candidates for all three catalog versions" >&2; exit 1; }
for candidate_id in $candidate_ids; do
  bindings="$("${NESTED_DOCKER[@]}" inspect --format '{{json .HostConfig.PortBindings}}' "$candidate_id")"
  [[ "$bindings" == null || "$bindings" == '{}' ]] || { echo "Candidate unexpectedly publishes a host port" >&2; exit 1; }
done
unowned_ids="$("${NESTED_DOCKER[@]}" ps -aq --filter "label=agentshield.managed=phase6.3" --filter "label=$LABEL_KEY!=$LABEL_VALUE")"
[[ -z "$unowned_ids" ]] || { echo "Found an unowned AgentShield candidate in the isolated daemon" >&2; exit 1; }

echo "Phase 6.3 actual Docker restoration passed in disposable containers and tmpfs database."
