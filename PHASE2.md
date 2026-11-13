# AgentShield Phase 2

The `agentshield` service is read-only. It polls the baseline ShopStack API
and deployer, stores timestamped observations, creates incidents for API
health failures, API error rate at or above 10%, and newly-created failed
deployment records, and records a deterministic diagnosis with the evidence.

Run it with `docker compose up -d --build agentshield`. Use `POST /monitor/run`
for an immediate scan, `GET /incidents` for detections, and
`GET /incidents/{id}/evidence` for saved evidence.

LLM diagnosis is opt-in: set `LLM_ENABLED=true`, `OPENAI_MODEL`, and
`OPENAI_API_KEY`, then call `POST /incidents/{id}/llm-diagnose`. It sends only
the selected incident summary and evidence, uses Responses with `store=False`,
and is not allowed to perform actions. Without all settings it returns 409.

Phase 2 performs no deployment, rollback, traffic management, failure injection,
or autonomous remediation. Those controls remain manual and separate.
