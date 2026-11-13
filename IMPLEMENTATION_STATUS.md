# AgentShield implementation status

## Implemented in this increment

- The Observer now defines an append-only evidence ledger with UUID evidence
  IDs, redacted content, SHA-256 integrity hashes, duplicate links, collection
  metadata, and integrity verification.
- Existing incident records remain readable. New evidence is associated with
  incidents without overwriting the legacy incident evidence field.
- The deterministic Incident Manager schema and legal state-transition graph
  are implemented, with transition audit records and low-confidence escalation
  paths.
- Rule diagnoses now produce hypotheses with evidence IDs and a supported
  recommended action. The preserved OpenAI compatibility endpoint receives
  redacted evidence only and remains diagnosis-only.
- The worker source now exposes read-only health and operational metrics on
  port 8004 after its next normal rebuild.
- The Safety Gate uses the architecture action vocabulary, R0-R3 classifications,
  service/dependency blast-radius analysis, action budget, cooldown, evidence
  integrity checks, snapshot requirements, expiring approval requests, and
  token-bound approver identity. Execution remains deliberately unavailable.
- A Rego policy artifact is included for the Gate's OPA endpoint integration.
- A local operator CLI wraps only the existing authenticated, TTL-bounded
  failure-injector API.

## Deferred, explicitly not enabled

- Docker resource, restart, and OOM telemetry requires a separate narrow
  read-only socket proxy; the Observer is not granted Docker access.
- Groq, Cloudflare, and LM Studio adapters are not enabled without provider
  configuration. The existing OpenAI compatibility path remains unchanged.
- Dashboard, SSE, and Telegram integrations remain deferred.
- Independent verification and recovery are not included in the current Phase 4 stage.

## Validation

- Syntax compilation passed for Observer, Safety Gate, worker, API, and CLI.
- Evidence/state tests: 4 passed.
- Safety Gate R0-R3 tests: 6 passed.
- Tests ran in disposable containers without starting, stopping, or recreating
  the active compose services and without connecting to the persistent database.


## Phase 4 increment

- Added a separate, disabled-by-default Executor with short-lived HMAC capabilities, persistent one-use replay protection, a fixed typed restart action, and an allowlisted pre-action snapshot.
- Added a custom Docker socket proxy that forwards only inspect/restart for `shopstack-api`; only that proxy mounts the Docker socket.
- The Safety Gate now commits approval decisions atomically and uses a conditional one-time execution claim before issuing a signed grant.
- No active service was restarted, rebuilt, or otherwise mutated. See `PHASE4.md` for the supported boundary and remaining limitations.
