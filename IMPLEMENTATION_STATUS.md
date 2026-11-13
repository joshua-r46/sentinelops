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
  token-bound approver identity. Phase 4 adds opt-in, narrowly gated execution.
- A Rego policy artifact is included for the Gate's OPA endpoint integration.
- A local operator CLI wraps only the existing authenticated, TTL-bounded
  failure-injector API.

## Deferred, explicitly not enabled

- Docker resource, restart, and OOM telemetry requires a separate narrow
  read-only socket proxy; the Observer is not granted Docker access.
- Groq, Cloudflare, and LM Studio adapters are not enabled without provider
  configuration. The existing OpenAI compatibility path remains unchanged.
- Dashboard, SSE, and Telegram integrations remain deferred.
- Automatic recovery remains deferred; independent verification is implemented in the Phase 5 increment below.

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

## Phase 5 increment

- Added an opt-in, independently deployed read-only Verifier with fixed HTTP probe targets and no Docker socket access.
- Baselines, consecutive post-action probes, error-rate/latency comparisons, and worker collateral health checks are associated with incident and execution IDs.
- Results are persisted as evidence and audit events; only passing verification resolves an incident, while failures escalate it.
- No automatic rollback or recovery was added. See PHASE5.md.

## Phase 6.1 increment

- Added an opt-in Snapshot Manager for allowlisted API identity/health and deployment ledger state.
- Snapshots bind to an approved execution and incident, are immutable through the service and database trigger, and are checked against a SHA-256 integrity digest on read.
- At the time of the Phase 6.1 increment, disposable integration validation covered authorization, approved-action binding, snapshot integrity, corruption detection, and audit events; see later entries for subsequent stages.

## Phase 6.2 increment

- Added a recovery eligibility/approval policy with incident, source execution, failed-verification, snapshot ownership, age, and typed-action checks.
- Snapshot HMAC-SHA256 signatures use a separately mounted secret file; the digest stored beside snapshot data is not treated as privileged-tampering protection. Legacy SHA-only snapshots are not recovery-eligible.
- Recovery decisions and rejections are recorded in an immutable, HMAC-chained audit ledger. The policy has no restoration endpoint or Docker access.
- Disposable recovery-policy tests cover validity, mismatched IDs, corrupted/expired snapshots, auth, replay/concurrency, limits, unsupported actions, and audit integrity.

## Phase 6.3 increment

- Added local `v1`, healthy `v2`, and intentionally failing `v2-bad` API images and a read-only catalog keyed by immutable local image IDs and approved launch profiles.
- Added a stable API router and a narrowly typed, HMAC-authenticated upstream switch. The Docker socket proxy creates and health-checks a candidate before cutover, retains incumbents, and makes at most one bounded compensation attempt.
- Recovery Policy issues an opt-in, one-use `rollback_deployment(api, version)` grant only after the existing eligibility and distinct approval checks. Executor independently verifies the grant, snapshot HMAC, image/config/limits against the catalog, and replay ledger.
- Recovery and audit results keep the incident escalated and require Phase 6.4 verification. Execution stays disabled by default. Only the proxy mounts the Docker socket.
- A prior disposable Docker integration pass is documented, but the outer Docker provisioning boundary has not been independently verified in this checkout. Treat that integration claim as unverified until a safe independent daemon is proven.

## Phase 6.4 increment

- Added independent post-restoration probes for router-reported deployment identity/version, service health, application readiness, metrics readiness, and read-only order lookup/input-validation journeys.
- Recovery Policy now preflights the verifier before starting a restoration, derives expected deployment identity from the integrity-checked snapshot, and requires a matching verifier result before recording recovery as verified.
- Only the verifier can transition an escalated incident through VERIFYING to RESOLVED. Failed or inconclusive checks return the incident to ESCALATED and write probe samples, timestamps, failure reasons, evidence hashes, and audit records.
- Unit tests use HTTP mocks and database test doubles. No live recovery or Docker integration has been run for this increment; independent live deployment verification remains unverified.

## Gemini and Telegram integration increment

- Extended the provider-neutral LLM Gateway with the official Google Gen AI Python SDK and Gemini environment configuration; retained the legacy OpenAI-compatible provider behind explicit provider selection.
- Gateway and Diagnosis Engine validate structured cause, confidence, uncertainty, typed recommendation fields, and evidence UUID membership. Recommendations are stored as diagnosis metadata and never authorize or execute actions.
- Expanded redaction for credentials, endpoints, common infrastructure identifiers, and IP addresses before cloud-provider calls.
- Telegram supports allowlisted private-user commands, incident/status/approval reads, and approve/deny calls through the existing Safety Gate. Safety Gate expiration, atomic decisions and its audit remain authoritative; Telegram stores durable update replay protection and a local action audit in a dedicated SQLite volume.
- Unit tests use mocked providers, HTTP responses, and temporary SQLite. No cloud or Telegram credentials were present in the process environment or configured `.env`, so no live smoke tests were run.
