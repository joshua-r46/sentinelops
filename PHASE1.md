# AgentShield Phase 1 — ShopStack target application

## Architecture

ShopStack is the Phase 1 target application. The baseline API on port 8000
creates PostgreSQL-backed orders and queues jobs in Redis. The worker consumes
those jobs and records `completed` or `failed`. PostgreSQL and Redis use named
volumes. The deployer on port 8001 is a separate, ledger-only change service.

`shopstack-api-v1-test` and `shopstack-api-v2-test` are isolated test
containers. V2 intentionally returns an error for order creation; it is not
routed to the baseline API and is never changed by this project.

## Change ledger

The deployer creates `requested` records and supports explicit, validated
transitions: `requested -> approved -> applied -> verified`, or
`requested|approved|applied -> failed`, then `applied|failed -> rolled_back`.
Every state timestamp is retained. `apply` and `rollback` only record an
operator action; they do not alter containers, traffic, images, or versions.
Startup migrations use `ADD COLUMN IF NOT EXISTS` and retain existing rows,
including the V2 ledger record.

## Run and validate

From this directory:

```bash
docker compose ps
curl http://localhost:8000/health
curl http://localhost:8001/health
curl -X POST http://localhost:8000/orders -H 'content-type: application/json' \
  -d '{"customer_name":"Phase 1","items":[{"sku":"demo","quantity":1}]}'
```

To rebuild only Phase 1 application services while preserving PostgreSQL,
Redis, volumes, and the V1/V2 containers:

```bash
FAILURE_INJECTOR_TOKEN=local-test-token docker compose up -d --build api worker deployer
```

## Controlled failures

Failure controls are disabled unless `FAILURE_INJECTOR_TOKEN` is supplied when
the API container starts. With the token, all controls are bounded by a
1–300-second Redis TTL and automatically expire:

```bash
TOKEN=local-test-token
curl -X POST http://localhost:8000/failure-scenarios/api_order_error \
  -H "X-Failure-Injector-Token: $TOKEN" -H 'content-type: application/json' \
  -d '{"duration_seconds":30}'
curl -X POST http://localhost:8000/failure-scenarios/api_order_latency_ms \
  -H "X-Failure-Injector-Token: $TOKEN" -H 'content-type: application/json' \
  -d '{"duration_seconds":30}'
curl -X POST http://localhost:8000/failure-scenarios/worker_job_failure \
  -H "X-Failure-Injector-Token: $TOKEN" -H 'content-type: application/json' \
  -d '{"duration_seconds":30}'
```

`api_order_error` makes only order creation return a deterministic 503.
`api_order_latency_ms` adds a fixed 250 ms delay to order creation.
`worker_job_failure` causes normally accepted jobs to end as `failed`.
Remove a scenario early with `DELETE` on the same URL and token.

## Limitations and Phase boundary

Phase 1 contains no detection pipeline, evidence collection, alerts, diagnosis,
LLM integration, traffic shifting, deployment automation, or autonomous
rollback. Failure injection does not stop dependencies or destroy data.
Phase 2 begins with observing these bounded signals and collecting evidence.
