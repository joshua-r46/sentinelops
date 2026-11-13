#!/usr/bin/env bash
# Connects to an independently provisioned disposable VM daemon. This helper
# deliberately does not provision a daemon through the current Docker engine.
set -Eeuo pipefail

isolated_docker_init() {
  : "${ISOLATED_DOCKER_HOST:?Set ISOLATED_DOCKER_HOST to the dedicated VM Docker API endpoint}"
  [[ "$ISOLATED_DOCKER_HOST" == tcp://* || "$ISOLATED_DOCKER_HOST" == ssh://* ]] || {
    echo "ISOLATED_DOCKER_HOST must be an explicit remote TCP/SSH endpoint" >&2; return 70;
  }
  [[ -z "${DOCKER_HOST:-}" && -z "${DOCKER_CONTEXT:-}" ]] || {
    echo "Clear ambient Docker endpoint/context variables" >&2; return 70;
  }
  export AGENTSHIELD_RUN_ID="${AGENTSHIELD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}"
  [[ "$AGENTSHIELD_RUN_ID" =~ ^[A-Za-z0-9-]{12,80}$ ]] || { echo "Invalid run identifier" >&2; return 70; }
  export AGENTSHIELD_LABEL_KEY="agentshield.test.run"
  export AGENTSHIELD_LABEL_VALUE="$AGENTSHIELD_RUN_ID"
  export DOCKER_CONFIG="$(mktemp -d "${TMPDIR:-/tmp}/agentshield-docker-${AGENTSHIELD_RUN_ID}.XXXXXX")"
  docker() { command docker --host "$ISOLATED_DOCKER_HOST" "$@"; }
  export -f docker
  local info
  info="$(docker info --format '{{.ID}}|{{.DockerRootDir}}|{{.Name}}' 2>/dev/null)" || {
    echo "Dedicated Docker endpoint is unavailable; refusing fallback" >&2; return 71;
  }
  [[ -n "$info" && "$info" != *"|/var/lib/docker|docker-desktop"* ]] || {
    echo "Docker endpoint identity is not an independent daemon" >&2; return 71;
  }
  export AGENTSHIELD_DOCKER_ID="${info%%|*}"
  [[ -n "$AGENTSHIELD_DOCKER_ID" ]] || { echo "Daemon identity check failed" >&2; return 71; }
}

isolated_resource_name() {
  local role="$1"
  [[ "$role" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || return 64
  printf 'as-%s-%s' "$role" "$AGENTSHIELD_RUN_ID"
}

isolated_cleanup() {
  local ids
  ids="$(docker ps -aq --filter "label=${AGENTSHIELD_LABEL_KEY}=${AGENTSHIELD_LABEL_VALUE}")" || return 1
  if [[ -n "$ids" ]]; then docker rm -f -- $ids >/dev/null || return 1; fi
  [[ -z "$(docker ps -aq --filter "label=${AGENTSHIELD_LABEL_KEY}=${AGENTSHIELD_LABEL_VALUE}")" ]]
}
