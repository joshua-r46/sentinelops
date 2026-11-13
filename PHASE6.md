# AgentShield Phase 6 — Recovery Manager

## Stage 6.1 — Snapshot Manager

This increment implements pre-action snapshots only. The Snapshot Manager is a
separate opt-in service in the Compose phase6 profile. It reads fixed ShopStack
API and deployer HTTP endpoints, has no Docker socket or shell access, and
requires a SNAPSHOT_TOKEN of at least 32 random bytes.

Snapshot requests must identify an existing gated incident and an approved
approved `restart_service` or `rollback_deployment` action targeting api. The
execution ID is the Safety Gate action ID. Captured content is limited to API identity/version, health/dependency state,
and up to 100 deployment ledger entries projected onto an explicit field
allowlist. Descriptions, secrets, environment variables, files, databases, and
host/container internals are not captured. There is no general application
configuration export endpoint in the current architecture, so runtime
configuration beyond this supported metadata is not snapshotted.

Each snapshot stores a UUID, incident ID, execution ID, target, timestamp,
content, and SHA-256 digest. The Stage 6.3 snapshot shape also includes the
active API image digest, configuration revision, and resource limits. Stage 6.1 added an immutability trigger and
digest check, but that digest is stored beside the data and is not protection
against a privileged database editor. Stage 6.2 adds an HMAC-SHA256 signature
over the snapshot ID, ownership IDs, target, timestamp, content, and digest.
Its key is mounted read-only from a separate protected file and is never stored
in the database. The recovery policy independently verifies this signature.
Legacy SHA-only snapshots remain readable but are not recovery-eligible.

## Validation

tests/run_phase6_snapshot_integration.sh uses only temporary ShopStack API and
deployer containers, PostgreSQL on tmpfs, Redis, and a labeled test network. It
checks approved-action binding, snapshot metadata/content, access control,
immutability, hash verification, tamper detection, and audit history.

## Stage status

Stages 6.1–6.4 are implemented in source. Phase 6.4 has unit-test coverage,
but has not been verified against a live restored deployment. Restoration is
opt-in and disabled by default; a successful Phase 6.3 cutover never resolves
an incident or retires an incumbent by itself.

## Stage 6.2 — Recovery Policy

The recovery policy accepts only an escalated incident with an executed,
human-approved API action and a linked Phase 5 FAILED verification. The
snapshot must match the incident and source execution, pass the external-key
HMAC check, and be within the configured age. The only policy action is the
typed `rollback_deployment(api, version)` request whose version exactly matches
the signed deployment snapshot. No arbitrary image, container ID, command,
mount, environment override, or Docker option is accepted.

A recovery operator token creates a pending request. A separate approver must
authorize it, and the requester cannot approve their own request. One active
request is permitted per incident, a snapshot and source execution cannot be
replayed, and accepted attempts are bounded per incident. Rejections and
decisions are written to the existing action history and an immutable,
HMAC-chained recovery audit ledger. The audit key is derived with domain
separation from the independently mounted integrity key.

The Recovery Policy has no Docker socket, shell, or general mutation interface.
When explicitly enabled, it sends a short-lived signed typed grant to the
isolated Executor. Snapshot integrity keys are mounted read-only from a
protected file outside the database and are never stored in snapshots or audit
events. The Executor independently verifies the snapshot signature and catalog.

tests/run_phase6_recovery_integration.sh exercises policy requests and audit
integrity using temporary containers and a database on tmpfs.

## Stage 6.3 — Candidate-first deployment restoration

`docker-compose.phase6.3.yml` is an opt-in deployment overlay. It provides
three local API variants behind the stable `api:8000` router. `deployment/catalog.json`
contains immutable local image IDs and fixed profiles for the internal
network, environment references, health endpoint, configuration revision, and
CPU/memory limits. The catalog is mounted read-only. The build/lock script
never pulls images and refuses to overwrite existing version tags.
The router persists only its active version and generated candidate ID in a
dedicated state volume; Executor has no access to that volume. Test routers use
tmpfs state.

The typed grant contains only `rollback_deployment`, service `api`, an
allowlisted version, and the signed snapshot envelope. Executor claims the
one-use nonce before calling the proxy. The proxy validates the digest is
present locally, constructs the Docker create request from the profile, starts
and health-checks a uniquely named candidate without host port publication,
then authenticates one router upstream switch. The prior backend stays live.
If the switch or immediate health check fails, the proxy tries one switch back
to the prior route. It removes only the candidate when safe; uncertain
compensation is reported without retrying. Phase 6.3 never retires an
incumbent.

Recovery Policy does not access Docker directly. When `RECOVERY_EXECUTOR_ENABLED`
and the Executor itself are explicitly enabled, it sends the typed grant to the
Executor, then asks the independent Verifier to check the restored deployment.
The request remains unverified unless the Verifier returns a matching evidence
record with a passing outcome and resolved incident state. The independent
Verifier is preflighted before approval is committed; a successful deployment
response by itself is never recovery proof.

`tests/run_phase6_3_disposable.sh` is intended to exercise candidate creation,
health-check, routing cutover, and restoration for all three versions on a
unique labeled Docker network with tmpfs PostgreSQL data. It was not run for
this Phase 6.4 task. The outer daemon provisioning boundary has not been
independently verified in the current checkout, so this script is not evidence
of safe independent Docker integration until that boundary is established.

## Stage 6.4 — Independent recovery verification

After Phase 6.3 returns, Recovery Policy sends the expected version and
deployment identity from the integrity-checked snapshot to the separate,
read-only Verifier. It has no Docker access. The Verifier samples the router
identity, API health, application root, metrics, side-effect-free order input
validation, and a read-only missing-order lookup multiple times. Every required
check must pass on every sample.

The Verifier claims the escalated incident under a row lock and records a
VERIFYING transition. Only a fully passing result transitions the incident to
RESOLVED. A failed result returns it to ESCALATED; transport errors, malformed
responses, and other uncertain probes are INCONCLUSIVE and also return it to
ESCALATED. Duplicate and concurrent requests are rejected. Each outcome stores
timestamps, all probe results, reasons, an evidence hash, evidence, state
transitions, and an audit event. Recovery Policy records the verifier outcome
in its existing HMAC-chained recovery audit ledger.

The unit tests use HTTP mocks and database test doubles. They do not prove
container identity, deployment cutover, or live ShopStack recovery. Those
integration claims require the separately isolated Docker environment.
