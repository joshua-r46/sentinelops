# AgentShield phase audit

Audit of task-local worktree at branch `phase4/executor-foundation`, baseline `3fd5889d751c14226e9b93f1b59112c8d7066412`. Existing worktree edits are preserved. This file records source presence, not production readiness.

| Phase | Existing sources and APIs | Tests | Current verification / gaps |
|---|---|---|---|
| 1 Infrastructure & Observer | `agentshield/main.py` polls ShopStack API, worker and deployer; `/health`, `/monitor/run`, `/incidents` | `test_phase2_core.py` | Observer is wired into Compose and persistent Postgres. Runtime detection has not been exercised in a disposable isolated stack in this session. |
| 2 Evidence & Incident Manager | Same module: redaction, evidence hashing/deduplication, incident states/transitions, evidence verification | `test_phase2_core.py` | Source and routes present; DB-backed integration unverified here. |
| 3 Diagnosis, LLM, planner | `diagnose_rules` and `/incidents/{id}/llm-diagnose`; newly added `llm_gateway.py` is provider-neutral, redacts input, constrains output and has no executor client | `test_phase3_policy.py`, new `test_llm_telegram_services.py` | Rule path present. Gateway is opt-in and must be supplied provider credentials/configuration. Live provider call is unverified. Remediation plans are persisted by Gate path; no complete user-facing planner workflow has been verified. |
| 4 Safety Gate, approval, Executor | `phase3policy/main.py`, `executor/main.py`, restricted `executor/socket_proxy.py` | `test_phase4_gate.py`, `test_phase4_executor.py`, `test_phase4_integration.py` | Authenticated, typed actions and approval code exist. Integration harness isolation is not proven; do not run against current host engine. Production Executor remains disabled by default. |
| 5 Independent Verifier & Recovery Manager | `agentshield/verifier.py`; Gate calls verifier after executor result | `test_phase5_verifier.py`, `test_phase5_disposable.py` | Source and Gate handoff exist; real disposable integration unverified. |
| 6 Snapshot, recovery, deployment restore | `snapshots.py`, `recovery_policy.py`, `api/router.py`, `executor/socket_proxy.py`; phase 6.3 Compose/catalog | `test_phase6_snapshot_integration.py`, `test_phase6_recovery_integration.py`, `test_phase6_3_executor.py` | Phase 6.3 source exists. `IMPLEMENTATION_STATUS.md` states Phase 6.4 independent verification/incumbent retirement is unfinished. Integration isolation and end-to-end recovery are unverified. |
| Telegram | Newly added `telegram.py`, Compose service; incident notification caller in Observer | new `test_llm_telegram_services.py` | Opt-in notification and allowlisted `/help` and `/status`; no infrastructure actions. Telegram delivery/polling and approval integration are not verified/implemented. |
| Dashboard | `api/dashboard.py`, included in `api/main.py`; existing static dashboard | `test_dashboard_adapter.py` | Live status/incidents/deployment reads supported. Approval queue, execution history, snapshot catalog and Phase 6.4 verification are explicitly unavailable because service read endpoints are absent. |

The separate local-only `mvp_demo.py` and `agentshield-mvp-demo.html` remain isolated as a simulated demo and are not evidence that the real phase integrations work.

## Isolation limitation

`tests/lib/isolated_docker.sh` requires an explicit remote daemon endpoint, but this checkout does not provision or prove an independently managed disposable VM daemon. Phase 4 still has the product Compose socket-proxy profile, and previous Phase 5/6 harnesses have not yet been fully migrated and executed against an independent daemon. Docker integration tests therefore remain unverified and must not be represented as passing.
