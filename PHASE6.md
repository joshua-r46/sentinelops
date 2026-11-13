# AgentShield Phase 6 — Recovery Manager

## Stage 6.1 — Snapshot Manager

This increment implements pre-action snapshots only. The Snapshot Manager is a
separate opt-in service in the Compose phase6 profile. It reads fixed ShopStack
API and deployer HTTP endpoints, has no Docker socket or shell access, and
requires a SNAPSHOT_TOKEN of at least 32 random bytes.

Snapshot requests must identify an existing gated incident and an approved
restart_service action targeting api. The execution ID is the Safety Gate action
ID. Captured content is limited to API identity/version, health/dependency state,
and up to 100 deployment ledger entries projected onto an explicit field
allowlist. Descriptions, secrets, environment variables, files, databases, and
host/container internals are not captured. There is no general application
configuration export endpoint in the current architecture, so runtime
configuration beyond this supported metadata is not snapshotted.

Each snapshot stores a UUID, incident ID, execution ID, target, timestamp,
content, and SHA-256 digest. Stage 6.1 added an immutability trigger and
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

## Not implemented yet

Stages 6.2–6.6 are not implemented in this increment. No recovery policy,
restoration action, Executor integration, recovery verification, or automatic
rollback is enabled.

## Stage 6.2 — Recovery Policy

The recovery policy accepts only an escalated incident with an executed,
human-approved API restart and a linked Phase 5 FAILED verification. The
snapshot must match the incident and source execution, pass the external-key
HMAC check, and be within the configured age. The only policy action is the
typed restore_api_deployment request whose version exactly matches the
snapshot's API version. No arbitrary arguments, target, shell, Docker access,
or restoration endpoint are exposed.

A recovery operator token creates a pending request. A separate approver must
authorize it, and the requester cannot approve their own request. One active
request is permitted per incident, a snapshot and source execution cannot be
replayed, and accepted attempts are bounded per incident. Rejections and
decisions are written to the existing action history and an immutable,
HMAC-chained recovery audit ledger. The audit key is derived with domain
separation from the independently mounted integrity key.

The service has no Executor client or Docker socket. Authorization only records
that the policy passed; it does not perform restoration. Snapshot integrity
keys must be supplied through SNAPSHOT_INTEGRITY_KEY_FILE from a protected
file outside the database and must not be stored in the database or committed.

tests/run_phase6_recovery_integration.sh exercises policy requests and audit
integrity using temporary containers and a database on tmpfs. Restoration is
not implemented in Stage 6.2.
