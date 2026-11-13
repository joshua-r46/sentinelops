# AgentShield Phase 5 — Independent Post-Action Verification

## Boundary

agentshield-verifier is a separate read-only HTTP probe service. It has no Docker
socket, Docker client, shell, Executor credentials, or user-controlled probe URL.
It can reach only its configured ShopStack API and worker URLs and writes
verification/audit history to the existing AgentShield database. The service is
opt-in through the Compose phase5 profile. Configure VERIFIER_TOKEN with at
least 32 random bytes.

Before executing an action, an operator or orchestrator records an authenticated
baseline with POST /baselines and {incident_id, target: "api"}. Baselines capture
healthy API state and its error rate, request counter, and average latency. A
baseline cannot be replaced after the incident enters execution or verification.

After the Safety Gate receives successful Executor acceptance, it sends the
incident ID and action ID (the Executor execution ID) to the verifier. The Gate
moves the incident to EXECUTING; the verifier atomically claims that execution
ID and moves the incident to VERIFYING before probing. Repeated calls cannot
verify the same execution twice.

The verifier performs three sequential probes by default. Every probe must show
healthy API status and healthy worker collateral status. API error rate and
median latency are compared with the recorded baseline and configured limits.
Missing baselines, failed probes, missing metrics, counter resets, excessive
errors, degraded latency, and unhealthy collateral all fail verification.
Only a fully passing result changes the incident to RESOLVED; every failed
result is recorded as FAILED and moves the incident to ESCALATED. A Docker
restart response alone never resolves an incident.

Each result is linked to both incident and execution IDs, stored with a SHA-256
evidence digest, added to the Observer evidence ledger, and written to the Gate
audit history. The service does not perform rollback or recovery.

## Validation

- tests/test_phase5_verifier.py covers passing probes, intermittent and
  persistent health failures, degraded latency, collateral failure, missing
  baseline, missing metrics, and stale/reset counters.
- tests/run_phase5_integration.sh builds and runs a disposable API, worker,
  verifier, PostgreSQL database on tmpfs, Redis, and test runner. It exercises
  authenticated baseline capture, three live probes, evidence/audit linkage,
  and the EXECUTING -> VERIFYING -> RESOLVED state path.
