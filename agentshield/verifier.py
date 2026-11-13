"""Independent, read-only post-action verification service.

The service probes fixed ShopStack HTTP endpoints. It has no Docker client,
socket, shell, or executor credentials; database access is limited to audit and
verification history shared with the Observer.
"""
import asyncio
import hashlib
import json
import os
import statistics
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import psycopg
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DB = os.getenv("DATABASE_URL", "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack")
TOKEN = os.getenv("VERIFIER_TOKEN", "")
API_URL = os.getenv("VERIFIER_API_URL", "http://api:8000").rstrip("/")
WORKER_URL = os.getenv("VERIFIER_WORKER_URL", "http://worker:8004").rstrip("/")
PROBE_COUNT = max(2, min(10, int(os.getenv("VERIFIER_PROBE_COUNT", "3"))))
PROBE_INTERVAL = max(0.0, min(10.0, float(os.getenv("VERIFIER_PROBE_INTERVAL", "1"))))
MAX_ERROR_RATE = float(os.getenv("VERIFIER_MAX_ERROR_RATE", "0.10"))
MAX_LATENCY_MULTIPLIER = float(os.getenv("VERIFIER_MAX_LATENCY_MULTIPLIER", "2.0"))
MAX_LATENCY_INCREASE_MS = float(os.getenv("VERIFIER_MAX_LATENCY_INCREASE_MS", "100"))
DEPENDENCIES = {"api": ("worker",)}
API_DEPENDENCIES = ("postgres", "redis")


def conn():
    return psycopg.connect(DB, row_factory=dict_row)


def now():
    return datetime.now(timezone.utc)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class BaselineRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: uuid.UUID
    target: str = Field(pattern=r"^api$")


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: uuid.UUID
    execution_id: uuid.UUID
    target: str = Field(pattern=r"^api$")


def init():
    with conn() as c:
        # These compatible CREATE IF NOT EXISTS statements make verifier startup
        # independent of container startup ordering while preserving Observer data.
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_incidents (
          id UUID PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
          status TEXT NOT NULL, first_seen_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL,
          summary TEXT NOT NULL, evidence JSONB NOT NULL, state TEXT NOT NULL DEFAULT 'DETECTED',
          service_name TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_evidence (
          id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id),
          source TEXT NOT NULL, kind TEXT NOT NULL, redacted_content JSONB NOT NULL,
          content_sha256 TEXT NOT NULL, duplicate_of UUID REFERENCES agentshield_evidence(id),
          collected_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_incident_transitions (
          id UUID PRIMARY KEY, incident_id UUID NOT NULL REFERENCES agentshield_incidents(id),
          from_state TEXT, to_state TEXT NOT NULL, reason TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_action_audit (
          id UUID PRIMARY KEY, action_request_id UUID, event_type TEXT NOT NULL,
          actor TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_verification_baselines (
          incident_id UUID NOT NULL REFERENCES agentshield_incidents(id), target TEXT NOT NULL,
          captured_at TIMESTAMPTZ NOT NULL, health JSONB NOT NULL, metrics JSONB NOT NULL,
          PRIMARY KEY (incident_id,target))""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_verifications (
          execution_id UUID PRIMARY KEY, incident_id UUID NOT NULL REFERENCES agentshield_incidents(id),
          target TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL,
          evidence JSONB NOT NULL, evidence_sha256 TEXT NOT NULL,
          started_at TIMESTAMPTZ NOT NULL, completed_at TIMESTAMPTZ NOT NULL)""")


async def fetch_probe(client: httpx.AsyncClient, service: str):
    base = API_URL if service == "api" else WORKER_URL
    health_response = await client.get(base + "/health")
    health = health_response.json()
    metrics = {}
    if service == "api":
        metrics_response = await client.get(base + "/metrics")
        metrics_response.raise_for_status()
        metrics = metrics_response.json()
    else:
        metrics = health
    return {"http_status": health_response.status_code, "health": health, "metrics": metrics}


async def capture_baseline(incident_id: uuid.UUID, target: str):
    async with httpx.AsyncClient(timeout=4.0, trust_env=False) as client:
        sample = await fetch_probe(client, target)
    if sample["http_status"] != 200 or sample["health"].get("status") != "healthy":
        raise HTTPException(409, "Cannot record a baseline while the target is unhealthy")
    metrics = sample["metrics"]
    if not isinstance(metrics.get("error_rate"), (int, float)) or not isinstance(metrics.get("average_latency_ms"), (int, float)):
        raise HTTPException(422, "Target metrics do not provide error rate and latency baseline fields")
    stamp = now()
    with conn() as c:
        incident = c.execute("SELECT state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (incident_id,)).fetchone()
        if not incident:
            raise HTTPException(404, "Incident not found")
        if incident["state"] in {"EXECUTING", "VERIFYING", "RESOLVED", "ESCALATED"}:
            raise HTTPException(409, "A pre-action baseline cannot be recorded in this incident state")
        baseline_insert = c.execute("""INSERT INTO agentshield_verification_baselines
          (incident_id,target,captured_at,health,metrics) VALUES (%s,%s,%s,%s,%s)
          ON CONFLICT (incident_id,target) DO NOTHING""",
          (incident_id, target, stamp, Jsonb(sample["health"]), Jsonb(metrics)))
        if baseline_insert.rowcount != 1:
            raise HTTPException(409, "A baseline is already recorded for this incident and target")
        c.execute("INSERT INTO agentshield_action_audit (id,action_request_id,event_type,actor,details,created_at) VALUES (%s,NULL,'verification_baseline_recorded','independent_verifier',%s,%s)",
                  (uuid.uuid4(), Jsonb({"incident_id": str(incident_id), "target": target, "captured_at": stamp.isoformat()}), stamp))
    return {"incident_id": incident_id, "target": target, "captured_at": stamp, "metrics": metrics}


def evaluate(samples: list[dict], baseline: dict | None):
    reasons = []
    if baseline is None:
        return "FAILED", ["missing_baseline"]
    if len(samples) < PROBE_COUNT:
        reasons.append("insufficient_consecutive_probes")
    if any(s.get("http_status") != 200 or s.get("health", {}).get("status") != "healthy" for s in samples):
        reasons.append("target_health_probe_failed")
    for service in API_DEPENDENCIES:
        if any(s.get("health", {}).get("dependencies", {}).get(service) != "connected" for s in samples):
            reasons.append("collateral_health_failed:" + service)
    for service in DEPENDENCIES["api"]:
        if any(s.get("collateral", {}).get(service, {}).get("http_status") != 200 or
               s.get("collateral", {}).get(service, {}).get("health", {}).get("status") != "healthy" for s in samples):
            reasons.append("collateral_health_failed:" + service)
            break
    metrics = [s.get("metrics", {}) for s in samples]
    if any(not isinstance(m.get("error_rate"), (int, float)) or
           not isinstance(m.get("average_latency_ms"), (int, float)) for m in metrics):
        reasons.append("target_metrics_missing")
    else:
        if isinstance(baseline.get("requests_total"), (int, float)) and any(
                not isinstance(m.get("requests_total"), (int, float)) or
                m["requests_total"] < baseline["requests_total"] for m in metrics):
            reasons.append("metrics_counter_reset_or_stale")
        error_rate = max(float(m["error_rate"]) for m in metrics)
        latency = statistics.median(float(m["average_latency_ms"]) for m in metrics)
        base_error = float(baseline.get("error_rate", 0))
        base_latency = float(baseline.get("average_latency_ms", 0))
        if error_rate > max(MAX_ERROR_RATE, base_error + 0.05):
            reasons.append("error_rate_above_baseline_threshold")
        latency_limit = max(base_latency * MAX_LATENCY_MULTIPLIER, base_latency + MAX_LATENCY_INCREASE_MS)
        if latency > latency_limit:
            reasons.append("latency_degraded_vs_baseline")
    return ("PASSED" if not reasons else "FAILED"), reasons


async def verify(incident_id: uuid.UUID, execution_id: uuid.UUID, target: str):
    if target != "api":
        raise HTTPException(422, "Verifier target is not allowlisted")
    started = now()
    with conn() as c:
        incident = c.execute("SELECT id,state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (incident_id,)).fetchone()
        if not incident:
            raise HTTPException(404, "Incident not found")
        baseline_row = c.execute("SELECT metrics FROM agentshield_verification_baselines WHERE incident_id=%s AND target=%s", (incident_id, target)).fetchone()
        baseline = baseline_row["metrics"] if baseline_row else None
        if incident["state"] != "EXECUTING":
            raise HTTPException(409, "Incident must be EXECUTING before independent verification")
        try:
            c.execute("INSERT INTO agentshield_verifications VALUES (%s,%s,%s,'VERIFYING','verification_in_progress',%s,%s,%s,%s)",
                      (execution_id, incident_id, target, Jsonb({}), digest({}), started, started))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "Execution has already been independently verified")
        c.execute("INSERT INTO agentshield_incident_transitions VALUES (%s,%s,'EXECUTING','VERIFYING','independent_verification_started',%s)",
                  (uuid.uuid4(), incident_id, started))
        c.execute("UPDATE agentshield_incidents SET state='VERIFYING',last_seen_at=%s WHERE id=%s", (started, incident_id))
    samples = []
    async with httpx.AsyncClient(timeout=4.0, trust_env=False) as client:
        for index in range(PROBE_COUNT):
            try:
                sample = await fetch_probe(client, target)
            except Exception as exc:
                sample = {"http_status": 0, "health": {"status": "unavailable", "error": type(exc).__name__}, "metrics": {}}
            collateral = {}
            for service in DEPENDENCIES[target]:
                try:
                    collateral[service] = await fetch_probe(client, service)
                except Exception as exc:
                    collateral[service] = {"http_status": 0, "health": {"status": "unavailable", "error": type(exc).__name__}, "metrics": {}}
            sample["collateral"] = collateral
            sample["probe"] = index + 1
            sample["observed_at"] = now().isoformat()
            samples.append(sample)
            if index + 1 < PROBE_COUNT and PROBE_INTERVAL:
                await asyncio.sleep(PROBE_INTERVAL)
    outcome, reasons = evaluate(samples, baseline)
    evidence = {"incident_id": str(incident_id), "execution_id": str(execution_id), "target": target,
                "baseline": baseline, "samples": samples, "outcome": outcome, "reasons": reasons}
    evidence_hash = digest(evidence)
    completed = now()
    next_state = "RESOLVED" if outcome == "PASSED" else "ESCALATED"
    with conn() as c:
        # Recheck terminal/verification state under lock; restart success alone
        # never changes an incident state.
        incident = c.execute("SELECT state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (incident_id,)).fetchone()
        if incident["state"] != "VERIFYING":
            raise HTTPException(409, "Incident left VERIFYING state before result commit")
        c.execute("UPDATE agentshield_verifications SET outcome=%s,reason=%s,evidence=%s,evidence_sha256=%s,completed_at=%s WHERE execution_id=%s AND incident_id=%s AND outcome='VERIFYING'",
                  (outcome, ";".join(reasons) or "all_checks_passed", Jsonb(evidence), evidence_hash, completed, execution_id, incident_id))
        evidence_id = uuid.uuid4()
        c.execute("INSERT INTO agentshield_evidence VALUES (%s,%s,'independent_verifier','post_action_verification',%s,%s,NULL,%s)",
                  (evidence_id, incident_id, Jsonb(evidence), evidence_hash, completed))
        c.execute("INSERT INTO agentshield_incident_transitions VALUES (%s,%s,'VERIFYING',%s,%s,%s)",
                  (uuid.uuid4(), incident_id, next_state, f"independent_verification_{outcome.lower()}", completed))
        c.execute("UPDATE agentshield_incidents SET state=%s,status=%s,last_seen_at=%s WHERE id=%s",
                  (next_state, "resolved" if outcome == "PASSED" else "open", completed, incident_id))
        audit_details = {"incident_id": str(incident_id), "execution_id": str(execution_id), "outcome": outcome,
                         "reasons": reasons, "evidence_id": str(evidence_id), "evidence_sha256": evidence_hash}
        c.execute("INSERT INTO agentshield_action_audit (id,action_request_id,event_type,actor,details,created_at) VALUES (%s,%s,%s,'independent_verifier',%s,%s)",
                  (uuid.uuid4(), execution_id, "verification_" + outcome.lower(), Jsonb(audit_details), completed))
    return {"incident_id": incident_id, "execution_id": execution_id, "outcome": outcome,
            "incident_state": next_state, "reasons": reasons, "evidence_id": evidence_id,
            "evidence_sha256": evidence_hash, "probes": len(samples)}


@asynccontextmanager
async def lifespan(app):
    init()
    yield


app = FastAPI(title="AgentShield Independent Verifier", lifespan=lifespan)


def authorize(token: str | None):
    import secrets
    if len(TOKEN.encode()) < 32:
        raise HTTPException(503, "Verifier authentication is not configured")
    if not token or not secrets.compare_digest(token, TOKEN):
        raise HTTPException(401 if not token else 403, "Verifier token is invalid")


@app.get("/health")
def health():
    return {"service": "agentshield-independent-verifier", "status": "healthy", "docker_access": "none"}


@app.post("/baselines", status_code=201)
async def baseline(request: BaselineRequest, x_verifier_token: str | None = Header(default=None)):
    authorize(x_verifier_token)
    return await capture_baseline(request.incident_id, request.target)


@app.post("/verify")
async def verify_action(request: VerificationRequest, x_verifier_token: str | None = Header(default=None)):
    authorize(x_verifier_token)
    return await verify(request.incident_id, request.execution_id, request.target)
