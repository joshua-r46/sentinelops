# AgentShield Phase 3 — action validation and governance

## Architecture and decisions

The independent agentshield-policy service runs on port 8003. It reads saved
Phase 2 incident evidence from PostgreSQL and writes only new Phase 3 action
requests, approvals, and append-only audit events. It has no HTTP client,
Docker socket/client, shell runner, cloud SDK, deployer URL, API URL, Redis URL,
or control-plane credentials. The monitor and optional LLM remain diagnosis-only
and never call it.

A proposal carries an incident UUID and SHA-256 of the exact saved evidence.
The policy service recomputes the hash, rejecting stale, invented, or
cross-incident evidence references. Evaluation is deterministic and
deny-by-default. operator_check is a non-mutating ALLOW. restart_service and
request_deployment_review are typed simulation-only actions that require human
approval. Unknown actions, shell/exec, delete, volume removal, database drops,
scale-to-zero, Docker API, rollback, arbitrary URLs, unknown targets, and
forbidden parameters are BLOCK.

Risk and blast radius are returned and stored with every decision. Consequential
actions are pending approval. Approval/rejection carries actor and note. Dry-run
is always non-mutating and audited; execute always returns 409 and audits the
attempt. Approval never grants infrastructure authority.

## API

- GET /health
- POST /actions; GET /actions/{id}
- POST /actions/{id}/approve, /reject, /dry-run, /execute
- GET /actions/{id}/audit

## Tests and validation

Executed validation:

    docker run --rm -v /home/joshua_r/projects/agentshield-workspace/shopstack/tests:/tests:ro agentshield:phase3-policy python -m unittest discover -s /tests

Result: 8 tests passed. They cover ALLOW, REQUIRE_APPROVAL, BLOCK,
malformed/unknown actions, privilege escalation, destructive operations,
arbitrary command/URL parameters, and typed deployment-review validation.

The live API check passed: invalid evidence returned 422; restart_service
returned REQUIRE_APPROVAL and pending_approval; approval transitioned it to
approved; dry-run returned would_mutate false and executed false; execute
returned 409; four audit events were retained. A destructive proposal returned
BLOCK, and a separate consequential proposal transitioned through rejection.
All currently-running pre-existing ShopStack, monitor, PostgreSQL, Redis,
worker, and deployer containers remained running.

## Limitations and next boundary

Phase 3 performs no deployment, restart, rollback, traffic change, failure
injection, Docker call, shell command, URL request, or data mutation outside its
own governance tables. It does not contact the monitor or LLM. Phase 4 may add
a separately reviewed least-privilege executor and safe snapshots/rollback;
this service must remain unable to execute infrastructure actions.
