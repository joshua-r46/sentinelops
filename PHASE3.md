# AgentShield Phase 3 — action validation and governance

## Architecture and decisions

The independent agentshield-policy service runs on port 8003. It reads saved
Phase 2 incident evidence from PostgreSQL and writes only new Phase 3 action
requests, approvals, and append-only audit events. It has no HTTP client,
Docker socket/client, shell runner, cloud SDK, deployer URL, API URL, Redis URL,
or control-plane credentials. The monitor and optional LLM remain diagnosis-only.
Gemini is accessed only through `agentshield/llm_gateway.py`; model
recommendations do not call or authorize the Safety Gate.

A proposal carries an incident UUID and SHA-256 of the exact saved evidence.
The policy service recomputes the hash, rejecting stale, invented, or
cross-incident evidence references. Evaluation is deterministic and
deny-by-default. Read-only `read_logs`, `read_metrics`, and `read_config`
actions are R0. Typed rollback/config restoration are R1 and require the
Executor's snapshot checks when execution is enabled. A bounded stateless
service restart is R1; API and PostgreSQL restarts and bounded resource changes
are R2 and require human approval. Unknown actions, shell/exec, delete, volume
removal, database drops, scale-to-zero, Docker API, arbitrary URLs, unknown
targets, and forbidden parameters are BLOCK.

Risk and blast radius are returned and stored with every decision. Consequential
actions are pending approval; API restarts are classified R2. Approval/rejection carries actor and note. Dry-run is always non-mutating and audited. The Phase 4 increment adds a
separate isolated Executor; execution remains disabled unless explicitly
configured, and the Executor accepts only its narrow signed action contract.
Approval remains bound to the exact proposal and expires.

## API

- GET /health
- POST /actions; GET /actions/{id}
- GET /approvals/pending (requires the Telegram queue service token)
- POST /actions/{id}/approve, /reject, /dry-run, /execute
- GET /actions/{id}/audit

## Gemini diagnosis and Telegram operator integration

The provider-neutral LLM Gateway supports Gemini through the official
`google-genai` SDK. Configure `LLM_ENABLED=true`, `LLM_PROVIDER=gemini`,
`GEMINI_API_KEY`, `GEMINI_MODEL`, and a 32-byte-or-longer `LLM_GATEWAY_TOKEN`.
Also set a separate 32-byte-or-longer `LLM_DIAGNOSIS_TOKEN`; callers must
authenticate before triggering a cloud request.
The legacy OpenAI-compatible REST provider remains available with
`LLM_PROVIDER=openai`, `LLM_API_KEY`, and `LLM_MODEL`. The gateway redacts
credential fields, connection endpoints, infrastructure IPs, and credential
patterns before sending evidence to either cloud provider. It validates
confidence, uncertainty, evidence UUIDs, and allowlisted typed recommendations.
The Diagnosis Engine persists these as diagnosis metadata only; operators still
submit any recommendation to the independent Safety Gate for evaluation.

Telegram supports private-chat `/help`, `/status`, `/incident <id>`,
`/start`, `/incidents`, `/approvals`, `/approve <id>`, and `/deny <id>`
commands. `/incidents` is a bounded read-only list; `/incident <id>` returns
one incident. Set
`TELEGRAM_ALLOWED_USER_IDS` to positive Telegram user IDs and enable polling
only when intended. `TELEGRAM_APPROVER_TOKEN` must match an entry in the Safety
Gate's `APPROVER_TOKENS_JSON`. The queue token is the internal
`TELEGRAM_SERVICE_TOKEN`. Telegram persists update offsets and replay/audit
records in its dedicated `telegram_state` volume. The Safety Gate owns approval
expiry, atomic decisions, duplicate rejection, and its existing action audit;
Telegram records command outcomes locally as well. No shell, Docker, or direct
Executor command is exposed.

The LLM Gateway records provider outcome and elapsed milliseconds in its
service log. It omits request/response bodies, credential values, and provider
error messages.

Unit tests mock Gemini SDK responses, internal APIs, and Telegram Bot API
responses. A real cloud or Telegram smoke test requires local credentials and
is reported separately from those tests.

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

The Phase 3 policy service itself has no Docker socket or shell access. Phase 4
adds an isolated Executor behind a route-filtering Docker proxy; see `PHASE4.md`
for its limited supported action and recovery behavior. The gate and monitor
remain separate from the Docker socket.
