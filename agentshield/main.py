"""AgentShield observer, evidence engine, incident manager, and diagnosis boundary.

This service only performs read-only HTTP observation.  It has no Docker SDK,
socket, shell runner, executor client, or infrastructure credentials.
"""
import asyncio
import hashlib
import json
import os
import re
import secrets
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
try:
    from llm_gateway import DiagnosisResponse
except ModuleNotFoundError:
    # Also support tests and local scripts that load this file by path while
    # starting from the repository root rather than the service workdir.
    from agentshield.llm_gateway import DiagnosisResponse

DB = os.getenv("DATABASE_URL", "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack")
API = os.getenv("SHOPSTACK_API_URL", "http://api:8000")
DEPLOYER = os.getenv("DEPLOYER_URL", "http://deployer:8001")
LLM_GATEWAY_URL = os.getenv("LLM_GATEWAY_URL", "http://agentshield-llm-gateway:8010").rstrip("/")
LLM_GATEWAY_TOKEN = os.getenv("LLM_GATEWAY_TOKEN", "")
LLM_DIAGNOSIS_TOKEN = os.getenv("LLM_DIAGNOSIS_TOKEN", "")
TELEGRAM_URL = os.getenv("TELEGRAM_SERVICE_URL", "http://agentshield-telegram:8011").rstrip("/")
TELEGRAM_SERVICE_TOKEN = os.getenv("TELEGRAM_SERVICE_TOKEN", "")
WORKER = os.getenv("WORKER_URL", "http://worker:8004")
INTERVAL = max(5, int(os.getenv("POLL_SECONDS", "15")))
ERROR_RATE_THRESHOLD = float(os.getenv("ERROR_RATE_THRESHOLD", "0.10"))
DEBOUNCE_SCANS = max(1, int(os.getenv("DEBOUNCE_SCANS", "2")))
LOW_CONFIDENCE = float(os.getenv("LOW_CONFIDENCE_THRESHOLD", "0.70"))
STARTED = datetime.now(timezone.utc)
SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "authorization", "api_key", "apikey", "credential"}
SECRET_PATTERN = re.compile(r"(?i)(bearer\s+|api[_-]?key[=:]\s*|token[=:]\s*|password[=:]\s*)[^\s,;]+")
SCAN_COUNTS: dict[str, int] = {}

STATE_TRANSITIONS = {
    "DETECTED": {"INVESTIGATING", "ESCALATED"},
    "INVESTIGATING": {"DIAGNOSED", "LOW_CONFIDENCE", "ESCALATED"},
    "DIAGNOSED": {"PLANNED", "ESCALATED"},
    "PLANNED": {"GATED", "ESCALATED"},
    "GATED": {"APPROVAL_PENDING", "EXECUTING", "BLOCKED", "ESCALATED"},
    "APPROVAL_PENDING": {"EXECUTING", "BLOCKED", "ESCALATED"},
    "EXECUTING": {"VERIFYING", "ESCALATED"},
    "VERIFYING": {"RESOLVED", "UNDONE", "ESCALATED"},
    "UNDONE": {"ESCALATED"},
    "LOW_CONFIDENCE": {"ESCALATED"},
    "BLOCKED": {"ESCALATED"},
    "RESOLVED": set(),
    "ESCALATED": set(),
}

def conn():
    return psycopg.connect(DB, row_factory=dict_row)

def now():
    return datetime.now(timezone.utc)

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)

def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def redact(value: Any) -> Any:
    """Treat logs and external payloads as data, never instructions."""
    if isinstance(value, dict):
        return {str(k): "[REDACTED]" if str(k).lower() in SENSITIVE_KEYS else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return SECRET_PATTERN.sub(r"\1[REDACTED]", value)
    return value

def init():
    with conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS agentshield_observations (id UUID PRIMARY KEY, observed_at TIMESTAMPTZ NOT NULL, source TEXT NOT NULL, healthy BOOLEAN, payload JSONB NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS agentshield_incidents (id UUID PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, first_seen_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL, summary TEXT NOT NULL, evidence JSONB NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS agentshield_diagnoses (id UUID PRIMARY KEY, incident_id UUID NOT NULL REFERENCES agentshield_incidents(id), created_at TIMESTAMPTZ NOT NULL, source TEXT NOT NULL, conclusion TEXT NOT NULL, confidence NUMERIC(3,2) NOT NULL, evidence JSONB NOT NULL)")
        c.execute("ALTER TABLE agentshield_incidents ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'DETECTED'")
        c.execute("ALTER TABLE agentshield_incidents ADD COLUMN IF NOT EXISTS service_name TEXT")
        c.execute("ALTER TABLE agentshield_diagnoses ADD COLUMN IF NOT EXISTS evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb")
        c.execute("ALTER TABLE agentshield_diagnoses ADD COLUMN IF NOT EXISTS action_type TEXT")
        c.execute("ALTER TABLE agentshield_diagnoses ADD COLUMN IF NOT EXISTS model_used TEXT")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_evidence (
          id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id),
          source TEXT NOT NULL, kind TEXT NOT NULL, redacted_content JSONB NOT NULL,
          content_sha256 TEXT NOT NULL, duplicate_of UUID REFERENCES agentshield_evidence(id),
          collected_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_incident_transitions (
          id UUID PRIMARY KEY, incident_id UUID NOT NULL REFERENCES agentshield_incidents(id),
          from_state TEXT, to_state TEXT NOT NULL, reason TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_hypotheses (
          id UUID PRIMARY KEY, incident_id UUID NOT NULL REFERENCES agentshield_incidents(id),
          cause TEXT NOT NULL, confidence NUMERIC(3,2) NOT NULL, evidence_ids JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_security_events (
          id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id),
          kind TEXT NOT NULL, detail TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")

def observe(source: str, healthy: bool, payload: Any):
    safe = redact(payload)
    with conn() as c:
        c.execute("INSERT INTO agentshield_observations VALUES (%s,%s,%s,%s,%s)", (uuid.uuid4(), now(), source, healthy, Jsonb(safe)))

def record_evidence(incident_id: uuid.UUID | None, source: str, kind: str, content: Any):
    safe = redact(content)
    content_hash = digest(safe)
    with conn() as c:
        old = c.execute("SELECT id FROM agentshield_evidence WHERE incident_id IS NOT DISTINCT FROM %s AND content_sha256=%s ORDER BY collected_at DESC LIMIT 1", (incident_id, content_hash)).fetchone()
        evidence_id = uuid.uuid4()
        c.execute("INSERT INTO agentshield_evidence VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (evidence_id, incident_id, source, kind, Jsonb(safe), content_hash, old["id"] if old else None, now()))
    return evidence_id

def create_incident(kind: str, service: str, summary: str, initial_evidence: dict):
    fingerprint = f"{kind}:{service}"
    safe = redact(initial_evidence)
    with conn() as c:
        old = c.execute("SELECT * FROM agentshield_incidents WHERE fingerprint=%s", (fingerprint,)).fetchone()
        if old:
            row = c.execute("UPDATE agentshield_incidents SET last_seen_at=%s,summary=%s,status='open' WHERE id=%s RETURNING *", (now(), summary, old["id"])).fetchone()
        else:
            row = c.execute("INSERT INTO agentshield_incidents (id,fingerprint,kind,status,first_seen_at,last_seen_at,summary,evidence,state,service_name) VALUES (%s,%s,%s,'open',%s,%s,%s,%s,'DETECTED',%s) RETURNING *", (uuid.uuid4(), fingerprint, kind, now(), now(), summary, Jsonb(safe), service)).fetchone()
            c.execute("INSERT INTO agentshield_incident_transitions VALUES (%s,%s,NULL,'DETECTED','detected',%s)", (uuid.uuid4(), row["id"], now()))
    return row

def transition(incident_id: uuid.UUID, target: str, reason: str):
    target = target.upper()
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_incidents WHERE id=%s", (incident_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Incident not found")
        source = row["state"] or "DETECTED"
        if target not in STATE_TRANSITIONS.get(source, set()):
            raise HTTPException(409, f"Invalid incident transition {source} -> {target}")
        updated = c.execute("UPDATE agentshield_incidents SET state=%s,last_seen_at=%s WHERE id=%s RETURNING *", (target, now(), incident_id)).fetchone()
        c.execute("INSERT INTO agentshield_incident_transitions VALUES (%s,%s,%s,%s,%s,%s)", (uuid.uuid4(), incident_id, source, target, reason, now()))
    return updated

def diagnose_rules(incident_id: uuid.UUID, kind: str, evidence_ids: list[uuid.UUID]):
    choices = {
        "api_unhealthy": ("dependency_or_api_unavailable", .80, "read_metrics"),
        "api_error_rate": ("api_error_rate_after_observed_failure", .80, "read_logs"),
        "deployment_failure": ("change_correlated_deployment_failure", .85, "rollback_deployment"),
        "ambiguous_multi_service": ("ambiguous_multi_service_failure", .30, None),
    }
    cause, confidence, action = choices.get(kind, ("unknown", .30, None))
    with conn() as c:
        hypothesis_id = uuid.uuid4()
        c.execute("INSERT INTO agentshield_hypotheses VALUES (%s,%s,%s,%s,%s,%s)", (hypothesis_id, incident_id, cause, confidence, Jsonb([str(x) for x in evidence_ids]), now()))
        diagnosis = c.execute("INSERT INTO agentshield_diagnoses (id,incident_id,created_at,source,conclusion,confidence,evidence,evidence_ids,action_type,model_used) VALUES (%s,%s,%s,'rules',%s,%s,%s,%s,%s,'rules') RETURNING *", (uuid.uuid4(), incident_id, now(), cause, confidence, Jsonb({"hypothesis_id": str(hypothesis_id)}), Jsonb([str(x) for x in evidence_ids]), action)).fetchone()
    if confidence < LOW_CONFIDENCE:
        transition(incident_id, "INVESTIGATING", "rule diagnosis started")
        transition(incident_id, "LOW_CONFIDENCE", "confidence below threshold")
        transition(incident_id, "ESCALATED", "uncertain diagnosis")
    else:
        transition(incident_id, "INVESTIGATING", "evidence collected")
        transition(incident_id, "DIAGNOSED", "deterministic rule diagnosis")
    return diagnosis

async def fetch_json(client: httpx.AsyncClient, url: str):
    response = await client.get(url)
    response.raise_for_status()
    return response.json()

async def scan():
    observed_at = now().isoformat()
    collected: dict[str, Any] = {"observed_at": observed_at}
    found: list[tuple[str, str, str]] = []
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            health, metrics = await asyncio.gather(fetch_json(client, API + "/health"), fetch_json(client, API + "/metrics"))
            collected["api"] = {"health": health, "metrics": metrics}
            observe("api", health.get("status") == "healthy", collected["api"])
            if health.get("status") != "healthy":
                found.append(("api_unhealthy", "api", "ShopStack API reported unhealthy"))
            elif metrics.get("requests_total", 0) > 0 and metrics.get("error_rate", 0) >= ERROR_RATE_THRESHOLD:
                found.append(("api_error_rate", "api", "ShopStack API error rate exceeded threshold"))
        except Exception as exc:
            collected["api"] = {"error": type(exc).__name__}
            observe("api", False, collected["api"])
            found.append(("api_unhealthy", "api", "ShopStack API could not be observed"))
        try:
            worker = await fetch_json(client, WORKER + "/metrics")
            collected["worker"] = worker
            observe("worker", worker.get("status") == "healthy", worker)
        except Exception as exc:
            collected["worker"] = {"collector": "unavailable", "error": type(exc).__name__}
            observe("worker", False, collected["worker"])
        try:
            deployments = await fetch_json(client, DEPLOYER + "/deployments")
            failed = [item for item in deployments if item.get("created_at", "") >= STARTED.isoformat() and item.get("status") in {"failed", "rolled_back"}]
            collected["deployments"] = {"failed": failed}
            observe("deployer", True, collected["deployments"])
            if failed:
                found.append(("deployment_failure", "deployer", "A newly observed deployment ledger entry failed"))
        except Exception as exc:
            collected["deployments"] = {"error": type(exc).__name__}
            observe("deployer", False, collected["deployments"])
    results = []
    for kind, service, summary in found:
        key = f"{kind}:{service}"
        SCAN_COUNTS[key] = SCAN_COUNTS.get(key, 0) + 1
        if SCAN_COUNTS[key] < DEBOUNCE_SCANS:
            continue
        incident = create_incident(kind, service, summary, collected)
        evidence_id = record_evidence(incident["id"], service, kind, collected)
        if incident["state"] == "DETECTED":
            diagnosis = diagnose_rules(incident["id"], kind, [evidence_id])
        else:
            diagnosis = None
        results.append({"incident": incident, "evidence_id": evidence_id, "diagnosis": diagnosis})
        if TELEGRAM_SERVICE_TOKEN:
            try:
                async with httpx.AsyncClient(timeout=4, trust_env=False) as notifier:
                    notification = await notifier.post(TELEGRAM_URL + "/notify",
                        headers={"Authorization": f"Bearer {TELEGRAM_SERVICE_TOKEN}"},
                        json={"text": f"AgentShield incident {incident['id']} detected for {service}: {summary}"})
                    notification.raise_for_status()
            except httpx.HTTPError:
                pass
    return {"evidence": redact(collected), "detections": results}

async def loop():
    while True:
        try:
            await scan()
        except Exception:
            pass
        await asyncio.sleep(INTERVAL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    init()
    task = asyncio.create_task(loop())
    yield
    task.cancel()

app = FastAPI(title="AgentShield Observer and Evidence Engine", lifespan=lifespan)

class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_state: str = Field(min_length=3, max_length=30)
    reason: str = Field(min_length=1, max_length=500)

@app.get("/health")
def health():
    return {"service": "agentshield", "status": "healthy", "mode": "read_only"}

@app.post("/monitor/run")
async def run():
    return await scan()

@app.get("/incidents")
def incidents():
    with conn() as c:
        return c.execute("SELECT * FROM agentshield_incidents ORDER BY last_seen_at DESC").fetchall()

@app.post("/incidents/{incident_id}/transition")
def transition_incident(incident_id: uuid.UUID, request: TransitionRequest):
    return transition(incident_id, request.target_state, request.reason)

@app.get("/incidents/{incident_id}/evidence")
def evidence(incident_id: uuid.UUID):
    with conn() as c:
        legacy = c.execute("SELECT evidence FROM agentshield_incidents WHERE id=%s", (incident_id,)).fetchone()
        rows = c.execute("SELECT * FROM agentshield_evidence WHERE incident_id=%s ORDER BY collected_at", (incident_id,)).fetchall()
    if not legacy:
        raise HTTPException(404, "Incident not found")
    return {"legacy_evidence": legacy["evidence"], "evidence": rows}

@app.get("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: uuid.UUID):
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_evidence WHERE id=%s", (evidence_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Evidence not found")
    return {"evidence_id": evidence_id, "valid": digest(row["redacted_content"]) == row["content_sha256"]}

@app.post("/incidents/{incident_id}/llm-diagnose")
def llm(incident_id: uuid.UUID, x_llm_diagnosis_token: str | None = Header(default=None)):
    if os.getenv("LLM_ENABLED", "false").lower() != "true":
        raise HTTPException(409, "LLM diagnosis is not configured")
    if len(LLM_GATEWAY_TOKEN.encode()) < 32:
        raise HTTPException(503, "LLM Gateway authorization is not configured")
    if len(LLM_DIAGNOSIS_TOKEN.encode()) < 32:
        raise HTTPException(503, "LLM diagnosis authorization is not configured")
    if not x_llm_diagnosis_token or not secrets.compare_digest(x_llm_diagnosis_token, LLM_DIAGNOSIS_TOKEN):
        raise HTTPException(401 if not x_llm_diagnosis_token else 403, "LLM diagnosis authorization is invalid")
    with conn() as c:
        incident = c.execute("SELECT * FROM agentshield_incidents WHERE id=%s", (incident_id,)).fetchone()
        evidence_rows = c.execute("SELECT id,redacted_content FROM agentshield_evidence WHERE incident_id=%s ORDER BY collected_at DESC LIMIT 20", (incident_id,)).fetchall()
    if not incident:
        raise HTTPException(404, "Incident not found")
    payload = {"summary": incident["summary"], "evidence": [{"id": str(row["id"]), "content": row["redacted_content"]} for row in evidence_rows]}
    try:
        with httpx.Client(timeout=25, trust_env=False) as gateway:
            response = gateway.post(LLM_GATEWAY_URL + "/diagnose", json=payload,
                                    headers={"Authorization": f"Bearer {LLM_GATEWAY_TOKEN}"})
            response.raise_for_status()
            result = DiagnosisResponse.model_validate(response.json())
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(502, "LLM Gateway diagnosis failed") from exc
    allowed_evidence_ids = {str(row["id"]) for row in evidence_rows}
    if not set(result.evidence_ids).issubset(allowed_evidence_ids):
        raise HTTPException(502, "LLM Gateway returned an invalid evidence reference")
    recommendation = {
        "action_type": result.recommended_action,
        "target": result.recommended_target,
        "parameters": result.recommended_parameters,
    }
    # A model recommendation is persisted as diagnosis metadata only. It is
    # never sent directly to the Executor or treated as a Safety Gate verdict.
    stored_evidence = redact({"redacted": True, "uncertainty": result.uncertainty,
                              "recommendation": recommendation, "provider": result.provider,
                              "model": result.model})
    with conn() as c:
        return c.execute("INSERT INTO agentshield_diagnoses (id,incident_id,created_at,source,conclusion,confidence,evidence,evidence_ids,action_type,model_used) VALUES (%s,%s,%s,'llm_gateway',%s,%s,%s,%s,%s,%s) RETURNING *", (uuid.uuid4(), incident_id, now(), redact(result.cause), result.confidence, Jsonb(stored_evidence), Jsonb(result.evidence_ids), None if result.recommended_action == "none" else result.recommended_action, f"{result.provider}:{result.model}")).fetchone()
