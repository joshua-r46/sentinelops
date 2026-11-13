#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
source "$ROOT/tests/lib/isolated_docker.sh"
isolated_docker_init

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$RANDOM-$RANDOM"
LABEL_KEY="agentshield.phase4.integration.run"
LABEL_VALUE="$RUN_ID"
PRIMARY_NETWORK="phase4-it-main-$RUN_ID"
SOCKET_NETWORK="phase4-it-socket-$RUN_ID"
POSTGRES="phase4-it-postgres-$RUN_ID"
REDIS="phase4-it-redis-$RUN_ID"
API="phase4-it-shopstack-api-$RUN_ID"
GATE="phase4-it-gate-$RUN_ID"
EXECUTOR="phase4-it-executor-$RUN_ID"
PROXY="phase4-it-proxy-$RUN_ID"
RUNNER_SUCCESS="phase4-it-runner-success-$RUN_ID"
RUNNER_FAILURE="phase4-it-runner-failure-$RUN_ID"
API_IMAGE="shopstack-api:phase4-integration-$RUN_ID"
GATE_IMAGE="agentshield:phase4-integration-gate-$RUN_ID"
EXECUTOR_IMAGE="agentshield:phase4-integration-executor-$RUN_ID"
PROXY_IMAGE="agentshield:phase4-integration-proxy-$RUN_ID"
PRIMARY_CREATED=0
SOCKET_CREATED=0
PG_PASSWORD="$(openssl rand -hex 24)"
EXECUTOR_SECRET="$(openssl rand -hex 32)"
EXECUTION_TOKEN="$(openssl rand -hex 32)"
APPROVER_TOKEN="$(openssl rand -hex 32)"
APPROVERS_JSON="{\"phase4-test-operator\":\"$APPROVER_TOKEN\"}"
DATABASE_URL="postgresql://shopstack_it:$PG_PASSWORD@$POSTGRES:5432/shopstack_it"

cleanup() {
  ids="$(docker ps -aq --filter "label=$LABEL_KEY=$LABEL_VALUE")"
  if [[ -n "$ids" ]]; then
    docker rm -fv $ids >/dev/null 2>&1 || true
  fi
  if [[ "$SOCKET_CREATED" == 1 ]]; then
    docker network rm "$SOCKET_NETWORK" >/dev/null 2>&1 || true
  fi
  if [[ "$PRIMARY_CREATED" == 1 ]]; then
    docker network rm "$PRIMARY_NETWORK" >/dev/null 2>&1 || true
  fi
  image_ids="$(docker image ls -q --filter "label=$LABEL_KEY=$LABEL_VALUE" | sort -u)"
  if [[ -n "$image_ids" ]]; then docker image rm $image_ids >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

for name in "$PRIMARY_NETWORK" "$SOCKET_NETWORK" "$POSTGRES" "$REDIS" "$API" "$GATE" "$EXECUTOR" "$PROXY"; do
  if docker container inspect "$name" >/dev/null 2>&1 || docker network inspect "$name" >/dev/null 2>&1; then
    echo "Refusing to use an existing Docker object named $name" >&2
    exit 2
  fi
done

docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$API_IMAGE" -f api/Dockerfile api
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$GATE_IMAGE" -f phase3policy/Dockerfile phase3policy
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$EXECUTOR_IMAGE" -f executor/Dockerfile executor
docker build --label "$LABEL_KEY=$LABEL_VALUE" -t "$PROXY_IMAGE" -f executor/Dockerfile.socket-proxy executor

docker network create --label "$LABEL_KEY=$LABEL_VALUE" "$PRIMARY_NETWORK" >/dev/null
PRIMARY_CREATED=1
docker network create --internal --label "$LABEL_KEY=$LABEL_VALUE" "$SOCKET_NETWORK" >/dev/null
SOCKET_CREATED=1

docker run -d --rm --name "$POSTGRES" --label "$LABEL_KEY=$LABEL_VALUE" \
  --network "$PRIMARY_NETWORK" \
  --tmpfs /var/lib/postgresql/data:rw,noexec,nosuid,size=256m \
  -e POSTGRES_DB=shopstack_it -e POSTGRES_USER=shopstack_it \
  -e POSTGRES_PASSWORD="$PG_PASSWORD" postgres:16-alpine >/dev/null

docker run -d --rm --name "$REDIS" --label "$LABEL_KEY=$LABEL_VALUE" \
  --network "$PRIMARY_NETWORK" redis:7-alpine redis-server --save "" --appendonly no >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$POSTGRES" pg_isready -q -U shopstack_it -d shopstack_it \
      && docker exec "$REDIS" redis-cli ping 2>/dev/null | grep -qx PONG; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "Disposable PostgreSQL/Redis did not become ready" >&2
  exit 1
fi

docker run -d --rm --name "$API" --label "$LABEL_KEY=$LABEL_VALUE" \
  --network "$PRIMARY_NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" -e REDIS_URL="redis://$REDIS:6379/0" \
  -e FAILURE_INJECTOR_TOKEN= "$API_IMAGE" >/dev/null

docker run -d --rm --name "$GATE" --label "$LABEL_KEY=$LABEL_VALUE" \
  --network "$PRIMARY_NETWORK" \
  -e DATABASE_URL="$DATABASE_URL" \
  -e APPROVER_TOKENS_JSON="$APPROVERS_JSON" \
  -e EXECUTOR_ENABLED=true -e EXECUTOR_URL="http://$EXECUTOR:8004" \
  -e EXECUTOR_SHARED_SECRET="$EXECUTOR_SECRET" -e EXECUTION_TOKEN="$EXECUTION_TOKEN" \
  "$GATE_IMAGE" >/dev/null

docker run -d --rm --name "$EXECUTOR" --label "$LABEL_KEY=$LABEL_VALUE" \
  --network "$PRIMARY_NETWORK" \
  --tmpfs /data:rw,noexec,nosuid,size=16m,uid=65532,gid=65532 \
  -e EXECUTOR_ENABLED=true -e EXECUTOR_SHARED_SECRET="$EXECUTOR_SECRET" \
  -e EXECUTOR_STATE_DB=/data/executor.sqlite3 \
  -e DOCKER_PROXY_URL="http://$PROXY:2375" \
  -e DOCKER_TARGET_CONTAINER="$API" \
  "$EXECUTOR_IMAGE" >/dev/null
docker network connect "$SOCKET_NETWORK" "$EXECUTOR"

docker run -d --rm --name "$PROXY" --label "$LABEL_KEY=$LABEL_VALUE" \
  --network "$SOCKET_NETWORK" --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  -e DOCKER_HOST="$ISOLATED_DOCKER_HOST" \
  -e ALLOWED_CONTAINER_NAME="$API" "$PROXY_IMAGE" >/dev/null

wait_for_http() {
  local url="$1"
  local ready=0
  for _ in $(seq 1 60); do
    if docker run --rm --label "$LABEL_KEY=$LABEL_VALUE" --network "$PRIMARY_NETWORK" "$GATE_IMAGE" \
        python -c "import urllib.request; urllib.request.urlopen('$url', timeout=2)" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" != 1 ]]; then
    echo "Disposable service did not become ready: $url" >&2
    return 1
  fi
}

wait_for_http "http://$API:8000/"
wait_for_http "http://$GATE:8003/health"
wait_for_http "http://$EXECUTOR:8004/health"

run_integration_pass() {
  local mode="$1"
  local runner="$2"
  docker create --rm --name "$runner" --label "$LABEL_KEY=$LABEL_VALUE" \
    --network "$PRIMARY_NETWORK" --workdir /work -e PYTHONDONTWRITEBYTECODE=1 \
    -e PHASE4_IT_MODE="$mode" -e PHASE4_IT_DATABASE_URL="$DATABASE_URL" \
    -e PHASE4_IT_GATE_URL="http://$GATE:8003" \
    -e PHASE4_IT_EXECUTOR_URL="http://$EXECUTOR:8004" \
    -e PHASE4_IT_PROXY_URL="http://$PROXY:2375" \
    -e PHASE4_IT_API_URL="http://$API:8000" \
    -e PHASE4_IT_TARGET_CONTAINER="$API" \
    -e PHASE4_IT_EXECUTOR_SECRET="$EXECUTOR_SECRET" \
    -e PHASE4_IT_EXECUTION_TOKEN="$EXECUTION_TOKEN" \
    -e PHASE4_IT_APPROVER_TOKEN="$APPROVER_TOKEN" \
    --mount "type=bind,source=$ROOT/tests/test_phase4_integration.py,target=/work/test_phase4_integration.py,readonly" \
    "$GATE_IMAGE" python -m unittest discover -v -s /work -p test_phase4_integration.py >/dev/null
  docker network connect "$SOCKET_NETWORK" "$runner"
  if ! docker start -a "$runner"; then
    for service in "$API" "$GATE" "$EXECUTOR" "$PROXY"; do docker logs "$service" >&2 || true; done
    return 1
  fi
}

run_integration_pass success "$RUNNER_SUCCESS"
# This stop targets only the uniquely named disposable API container created above.
docker stop "$API" >/dev/null
run_integration_pass docker_failure "$RUNNER_FAILURE"

echo "Phase 4 disposable integration passed. Active ShopStack containers and named volumes were not used."
