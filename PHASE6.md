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
content, and SHA-256 digest. The database rejects update and delete operations
on stored snapshots. Reads recheck the digest; a mismatch returns a conflict and
writes an integrity-failure audit event. Create/read operations require the
snapshot token. No update or delete HTTP routes exist.

## Validation

tests/run_phase6_snapshot_integration.sh uses only temporary ShopStack API and
deployer containers, PostgreSQL on tmpfs, Redis, and a labeled test network. It
checks approved-action binding, snapshot metadata/content, access control,
immutability, hash verification, tamper detection, and audit history.

## Not implemented yet

Stages 6.2–6.6 are not implemented in this increment. No recovery policy,
restoration action, Executor integration, recovery verification, or automatic
rollback is enabled.
