# AgentShield Phase 4 — isolated executor foundation

## Scope and boundary

Phase 4 adds a separate Executor, a filtered Docker socket proxy, and short-lived
Safety Gate capabilities. The Executor has no direct Docker socket, shell, cloud,
or target application credentials. The host-facing execute endpoint requires a
separate operator token. The Safety Gate signs one-use grants with a shared
secret; the Executor checks the signature, action, Gate state, expiry, proposal
digest, and persistent nonce/action ID before it contacts the proxy. The SQLite
execution ledger is stored in the dedicated executor_state volume.

The only live operation currently supported is restart_service for the configured
single container name (default shopstack-api). The API restart is classified R2
and requires human approval before Gate dispatch. Other targets, action types,
Docker routes, methods, and arbitrary parameters fail closed. The proxy returns
a reduced container inspection record and filters environment variables, mounts,
and other container configuration. The Executor records an allowlisted
pre-action snapshot and issues one restart request. Independent post-action
verification and recovery are not part of this stage. The Gate atomically claims
an action before dispatch and commits an approval and its state transition under
a row lock. Replays are rejected at both layers.

EXECUTOR_ENABLED defaults to false; the Executor and Docker proxy are in the
opt-in Compose phase4 profile. The Executor has no host-published port. The
Docker proxy is attached only to the private executor socket network and is not
reachable from the monitor. Only the proxy mounts the Docker socket. The Docker
group ID must match the host socket (DOCKER_GID).

## Limits for this stage

The Executor records a failed attempt when inspection or restart fails and does
not retry that action ID. It does not independently verify the post-restart
state, automatically roll back, or provide a recovery endpoint. If a Docker
response is ambiguous, an operator must inspect the service outside this
workflow before proposing another action.

Read-only actions, deployment rollback, config restore, resource-limit changes,
and restarts of other services are not implemented by the Executor. Dry-run
remains non-mutating. Integration validation uses uniquely named disposable
containers and a temporary database only.

## Tests

The phase4 executor tests cover signed authorization, expiry, approval state,
unsupported operations, duplicate and concurrent replay, snapshots, secret
filtering, preflight failure, and Docker failure. Gate tests cover operator-token
enforcement and concurrent approval atomicity. The integration test exercises
the proposal-to-proxy path with a disposable ShopStack API, temporary PostgreSQL
and Redis, a Gate, an Executor, and the filtered proxy.
