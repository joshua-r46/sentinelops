"""AgentShield Phase 3 safety gate.

The gate evaluates typed proposals and issues short-lived, signed capabilities
to the isolated Phase 4 Executor. It has no Docker socket or shell capability.
"""
import hashlib
import hmac
import json
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import psycopg
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

DB = os.getenv("DATABASE_URL", "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack")
OPA_URL = os.getenv("OPA_URL", "").rstrip("/")
EXECUTOR_ENABLED = os.getenv("EXECUTOR_ENABLED", "false").lower() == "true"
EXECUTOR_URL = os.getenv("EXECUTOR_URL", "").rstrip("/")
EXECUTOR_SHARED_SECRET = os.getenv("EXECUTOR_SHARED_SECRET", "")
EXECUTION_TOKEN = os.getenv("EXECUTION_TOKEN", "")
VERIFIER_URL = os.getenv("VERIFIER_URL", "").rstrip("/")
VERIFIER_TOKEN = os.getenv("VERIFIER_TOKEN", "")
TELEGRAM_QUEUE_TOKEN = os.getenv("TELEGRAM_QUEUE_TOKEN", "")
APPROVER_TOKENS = json.loads(os.getenv("APPROVER_TOKENS_JSON", "{}"))
APPROVAL_TTL_SECONDS = max(60, int(os.getenv("APPROVAL_TTL_SECONDS", "900")))
COOLDOWN_SECONDS = max(0, int(os.getenv("ACTION_COOLDOWN_SECONDS", "300")))
MAX_ACTIONS_PER_INCIDENT = 3
SERVICES = {"api", "worker", "deployer", "redis", "postgres"}
DEPENDENCIES = {"api": {"redis", "postgres"}, "worker": {"redis", "postgres"}, "deployer": {"postgres"}, "redis": set(), "postgres": set()}
ACTION_TYPES = {"read_logs", "read_metrics", "read_config", "rollback_deployment", "restore_config", "restart_service", "set_resource_limit"}
R3_TYPES = {"shell", "exec", "delete", "remove_volume", "drop_database", "scale_to_zero", "docker", "docker_api", "http_request", "webhook"}

def conn():
    return psycopg.connect(DB, row_factory=dict_row)
def now():
    return datetime.now(timezone.utc)
def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def init():
    with conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_action_requests (
          id UUID PRIMARY KEY, incident_id UUID NOT NULL, action_type TEXT NOT NULL,
          parameters JSONB NOT NULL, evidence_sha256 TEXT NOT NULL, decision TEXT NOT NULL,
          reason TEXT NOT NULL, risk TEXT NOT NULL, blast_radius JSONB NOT NULL,
          status TEXT NOT NULL, dry_run BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_action_approvals (
          id UUID PRIMARY KEY, action_request_id UUID NOT NULL REFERENCES agentshield_action_requests(id),
          decision TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_action_audit (
          id UUID PRIMARY KEY, action_request_id UUID, event_type TEXT NOT NULL,
          actor TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)""")
        c.execute("ALTER TABLE agentshield_action_requests ADD COLUMN IF NOT EXISTS evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb")
        c.execute("ALTER TABLE agentshield_action_requests ADD COLUMN IF NOT EXISTS diagnosis_id UUID")
        c.execute("ALTER TABLE agentshield_action_requests ADD COLUMN IF NOT EXISTS reversibility TEXT NOT NULL DEFAULT 'unknown'")
        c.execute("ALTER TABLE agentshield_action_requests ADD COLUMN IF NOT EXISTS snapshot_required BOOLEAN NOT NULL DEFAULT FALSE")
        c.execute("ALTER TABLE agentshield_action_requests ADD COLUMN IF NOT EXISTS approval_expires_at TIMESTAMPTZ")
        c.execute("ALTER TABLE agentshield_action_requests ADD COLUMN IF NOT EXISTS proposal_sha256 TEXT")
        c.execute("ALTER TABLE agentshield_action_approvals ADD COLUMN IF NOT EXISTS proposal_sha256 TEXT")

def audit(action_id: uuid.UUID | None, event: str, actor: str, details: dict):
    with conn() as c:
        c.execute("INSERT INTO agentshield_action_audit VALUES (%s,%s,%s,%s,%s,%s)", (uuid.uuid4(), action_id, event, actor, Jsonb(details), now()))

class EvidenceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: uuid.UUID
    evidence_ids: list[uuid.UUID] = Field(default_factory=list, max_length=20)
    evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

class ActionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=80)
    parameters: dict[str, Any] = Field(default_factory=dict)

class ProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence: EvidenceReference
    action: ActionProposal
    diagnosis_id: uuid.UUID | None = None

class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(default="", max_length=500)

def validate_evidence(ref: EvidenceReference):
    with conn() as c:
        incident = c.execute("SELECT evidence FROM agentshield_incidents WHERE id=%s", (ref.incident_id,)).fetchone()
        rows = c.execute("SELECT id,redacted_content,content_sha256 FROM agentshield_evidence WHERE incident_id=%s AND id = ANY(%s)", (ref.incident_id, ref.evidence_ids)).fetchall() if ref.evidence_ids else []
    if not incident:
        raise HTTPException(422, "Evidence reference does not identify an incident")
    if ref.evidence_ids and len(rows) != len(ref.evidence_ids):
        raise HTTPException(422, "Evidence IDs must belong to the incident")
    if rows:
        for row in rows:
            if digest(row["redacted_content"]) != row["content_sha256"]:
                raise HTTPException(422, "Evidence integrity verification failed")
        return [str(row["id"]) for row in rows], digest([{"id": str(row["id"]), "hash": row["content_sha256"]} for row in rows])
    # Compatibility path for Phase 2 historical incidents only.
    if not ref.evidence_sha256 or digest(incident["evidence"]) != ref.evidence_sha256:
        raise HTTPException(422, "Evidence hash does not match preserved incident evidence")
    return [], ref.evidence_sha256

def validate_action(action: ActionProposal):
    action_type = action.action_type.lower().strip()
    target = action.target.lower().strip()
    params = action.parameters
    if action_type in R3_TYPES or action_type not in ACTION_TYPES:
        return "BLOCK", "R3", "Irreversible, arbitrary, or unknown action is blocked.", {"services": [], "scope": "none"}, False, "prohibited"
    if target not in SERVICES:
        return "BLOCK", "R3", "Target is outside the service allowlist.", {"services": [], "scope": "none"}, False, "prohibited"
    if {"command", "shell", "url", "uri", "docker", "endpoint", "token"}.intersection(params):
        return "BLOCK", "R3", "Arbitrary commands, URLs, Docker access, and credentials are forbidden.", {"services": [], "scope": "none"}, False, "prohibited"
    if action_type in {"read_logs", "read_metrics", "read_config"}:
        if params:
            return "BLOCK", "R3", "Read-only actions accept no parameters.", {"services": [target], "scope": "single_service"}, False, "prohibited"
        return "ALLOW", "R0", "Read-only typed action is permitted.", {"services": [target], "scope": "single_service"}, False, "read_only"
    if action_type == "rollback_deployment":
        if target != "api" or set(params) != {"version"} or not isinstance(params["version"], str) or not params["version"]:
            return "BLOCK", "R3", "rollback_deployment is limited to api with a non-empty version.", {"services": [target], "scope": "none"}, False, "prohibited"
        return "ALLOW", "R1", "Reversible deployment rollback requires a snapshot when an executor exists.", {"services": ["api"], "scope": "single_service"}, True, "reversible"
    if action_type == "restore_config":
        if set(params) != {"revision"} or not isinstance(params["revision"], str) or not params["revision"]:
            return "BLOCK", "R3", "restore_config requires only a non-empty revision.", {"services": [target], "scope": "none"}, False, "prohibited"
        return "ALLOW", "R1", "Reversible config restoration requires a snapshot when an executor exists.", {"services": [target], "scope": "single_service"}, True, "reversible"
    if action_type == "restart_service":
        if params:
            return "BLOCK", "R3", "restart_service accepts no parameters.", {"services": [target], "scope": "none"}, False, "prohibited"
        affected = sorted({target, *[service for service, deps in DEPENDENCIES.items() if target in deps]})
        if target == "postgres":
            return "REQUIRE_APPROVAL", "R2", "Restarting postgres affects dependent services and needs approval.", {"services": affected, "scope": "dependency_impact"}, True, "reversible"
        if target == "api":
            return "REQUIRE_APPROVAL", "R2", "Restarting api affects live traffic and requires human approval.", {"services": affected, "scope": "single_service"}, True, "reversible"
        return "ALLOW", "R1", "Stateless or dependency restart is reversible.", {"services": affected, "scope": "single_service"}, True, "reversible"
    if action_type == "set_resource_limit":
        if set(params) != {"cpu", "memory"} or not isinstance(params["cpu"], (int, float)) or not isinstance(params["memory"], int):
            return "BLOCK", "R3", "set_resource_limit requires numeric cpu and integer memory.", {"services": [target], "scope": "none"}, False, "prohibited"
        if not (0.1 <= float(params["cpu"]) <= 4 and 64 <= params["memory"] <= 4096):
            return "BLOCK", "R3", "Resource limits exceed bounded safe values.", {"services": [target], "scope": "none"}, False, "prohibited"
        return "REQUIRE_APPROVAL", "R2", "Resource changes are consequential and require approval.", {"services": [target], "scope": "single_service"}, True, "reversible"
    return "BLOCK", "R3", "Policy evaluation failed closed.", {"services": [], "scope": "none"}, False, "prohibited"

def budget_and_cooldown(incident_id: uuid.UUID, action: ActionProposal):
    with conn() as c:
        used = c.execute("SELECT count(*) AS total FROM agentshield_action_requests WHERE incident_id=%s AND decision != 'BLOCK'", (incident_id,)).fetchone()["total"]
        last = c.execute("SELECT created_at FROM agentshield_action_requests WHERE incident_id=%s AND action_type=%s AND parameters->>'target'=%s ORDER BY created_at DESC LIMIT 1", (incident_id, action.action_type, action.target)).fetchone()
    if used >= MAX_ACTIONS_PER_INCIDENT:
        return "Maximum of three non-blocked actions per incident has been reached."
    if last and (now() - last["created_at"]).total_seconds() < COOLDOWN_SECONDS:
        return "Action cooldown is active for this incident and target."
    return None

def opa_check(input_data: dict):
    if not OPA_URL:
        return True, {"engine": "opa", "status": "not_configured", "fallback": "deterministic_gate"}
    try:
        response = httpx.post(OPA_URL + "/v1/data/agentshield/allow", json={"input": input_data}, timeout=2)
        response.raise_for_status()
        result = response.json().get("result", False)
        return bool(result), {"engine": "opa", "status": "evaluated", "result": result}
    except Exception as exc:
        return False, {"engine": "opa", "status": "unavailable_fail_closed", "error": type(exc).__name__}

def require_approver(token: str | None):
    if not token:
        raise HTTPException(401, "Approval token is required")
    for actor, configured in APPROVER_TOKENS.items():
        if isinstance(configured, str) and secrets.compare_digest(token, configured):
            return actor
    raise HTTPException(403, "Approval token is not authorized")

def require_telegram_queue(token: str | None):
    if len(TELEGRAM_QUEUE_TOKEN.encode()) < 32:
        raise HTTPException(503, "Telegram approval queue access is not configured")
    if not token:
        raise HTTPException(401, "Telegram approval queue authorization required")
    if not secrets.compare_digest(token, TELEGRAM_QUEUE_TOKEN):
        raise HTTPException(403, "Telegram approval queue authorization is invalid")

@asynccontextmanager
async def lifespan(app):
    init()
    yield

app = FastAPI(title="AgentShield Safety Gate", lifespan=lifespan)

@app.get("/health")
def health():
    executor_ready = EXECUTOR_ENABLED and bool(EXECUTOR_URL) and len(EXECUTOR_SHARED_SECRET.encode()) >= 32
    return {"service": "agentshield-phase3-policy", "status": "healthy", "mode": "validation_and_gated_execution",
            "executor": "enabled" if executor_ready else "disabled", "opa_configured": bool(OPA_URL)}

@app.post("/actions", status_code=201)
def propose(request: ProposalRequest):
    evidence_ids, evidence_sha = validate_evidence(request.evidence)
    decision, risk, reason, blast, snapshot, reversibility = validate_action(request.action)
    budget_reason = budget_and_cooldown(request.evidence.incident_id, request.action) if decision != "BLOCK" else None
    if budget_reason:
        decision, risk, reason = "BLOCK", "R3", budget_reason
    opa_allowed, policy_trace = opa_check({"action_type": request.action.action_type, "target": request.action.target, "risk": risk, "decision": decision})
    if not opa_allowed:
        decision, risk, reason = "BLOCK", "R3", "OPA policy denied or was unavailable."
    action_id, created = uuid.uuid4(), now()
    status = "blocked" if decision == "BLOCK" else ("pending_approval" if decision == "REQUIRE_APPROVAL" else "validated")
    expires = created + timedelta(seconds=APPROVAL_TTL_SECONDS) if decision == "REQUIRE_APPROVAL" else None
    parameters = {"target": request.action.target, **request.action.parameters}
    proposal_hash = digest({"incident_id": str(request.evidence.incident_id), "evidence_ids": evidence_ids, "action_type": request.action.action_type, "parameters": parameters, "diagnosis_id": str(request.diagnosis_id) if request.diagnosis_id else None})
    record = {"id": action_id, "incident_id": request.evidence.incident_id, "action_type": request.action.action_type, "parameters": parameters, "evidence_sha256": evidence_sha, "decision": decision, "reason": reason, "risk": risk, "blast_radius": blast, "status": status, "dry_run": True, "created_at": created, "updated_at": created, "evidence_ids": evidence_ids, "diagnosis_id": request.diagnosis_id, "reversibility": reversibility, "snapshot_required": snapshot, "approval_expires_at": expires, "proposal_sha256": proposal_hash}
    with conn() as c:
        c.execute("""INSERT INTO agentshield_action_requests (id,incident_id,action_type,parameters,evidence_sha256,decision,reason,risk,blast_radius,status,dry_run,created_at,updated_at,evidence_ids,diagnosis_id,reversibility,snapshot_required,approval_expires_at,proposal_sha256)
        VALUES (%(id)s,%(incident_id)s,%(action_type)s,%(parameters)s,%(evidence_sha256)s,%(decision)s,%(reason)s,%(risk)s,%(blast_radius)s,%(status)s,%(dry_run)s,%(created_at)s,%(updated_at)s,%(evidence_ids)s,%(diagnosis_id)s,%(reversibility)s,%(snapshot_required)s,%(approval_expires_at)s,%(proposal_sha256)s)""", {**record, "parameters": Jsonb(parameters), "blast_radius": Jsonb(blast), "evidence_ids": Jsonb(evidence_ids)})
    audit(action_id, "gate_decision", "safety_gate", {"decision": decision, "risk": risk, "reason": reason, "policy_trace": policy_trace, "dry_run": True})
    return record

def get_action(action_id: uuid.UUID):
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_action_requests WHERE id=%s", (action_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Action request not found")
    return row

@app.get("/actions/{action_id}")
def action(action_id: uuid.UUID):
    return get_action(action_id)

@app.get("/approvals/pending")
def pending_approvals(x_telegram_queue_token: str | None = Header(default=None)):
    """Read-only bounded approval queue for the authenticated Telegram service."""
    require_telegram_queue(x_telegram_queue_token)
    with conn() as c:
        rows = c.execute("""SELECT id,incident_id,action_type,parameters,reason,risk,
          approval_expires_at,created_at FROM agentshield_action_requests
          WHERE decision='REQUIRE_APPROVAL' AND status='pending_approval'
            AND approval_expires_at > %s ORDER BY created_at ASC LIMIT 100""", (now(),)).fetchall()
    return {"items": rows}

def decide(action_id: uuid.UUID, request: ApprovalRequest, decision: str, token: str | None):
    actor = require_approver(token)
    expired = False
    with conn() as c:
        # Lock the request and commit the decision + approval record together.
        # Competing approve/reject requests serialize on this row.
        row = c.execute("SELECT * FROM agentshield_action_requests WHERE id=%s FOR UPDATE", (action_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Action request not found")
        if row["decision"] != "REQUIRE_APPROVAL" or row["status"] != "pending_approval":
            raise HTTPException(409, "This action is not awaiting approval")
        current = now()
        if row["approval_expires_at"] and current >= row["approval_expires_at"]:
            c.execute("UPDATE agentshield_action_requests SET status='expired',updated_at=%s WHERE id=%s AND status='pending_approval'", (current, action_id))
            expired = True
        else:
            status = "approved" if decision == "approved" else "rejected"
            updated = c.execute("UPDATE agentshield_action_requests SET status=%s,updated_at=%s WHERE id=%s AND status='pending_approval' RETURNING *", (status, current, action_id)).fetchone()
            if not updated:
                raise HTTPException(409, "This action was already decided")
            c.execute("INSERT INTO agentshield_action_approvals (id,action_request_id,decision,actor,note,created_at,proposal_sha256) VALUES (%s,%s,%s,%s,%s,%s,%s)", (uuid.uuid4(), action_id, decision, actor, request.note, current, row["proposal_sha256"]))
    if expired:
        audit(action_id, "approval_expired", "safety_gate", {})
        raise HTTPException(409, "Approval request expired")
    audit(action_id, "approval_" + decision, actor, {"note": request.note, "proposal_sha256": row["proposal_sha256"]})
    return updated

@app.post("/actions/{action_id}/approve")
def approve(action_id: uuid.UUID, request: ApprovalRequest, x_approval_token: str | None = Header(default=None)):
    return decide(action_id, request, "approved", x_approval_token)

@app.post("/actions/{action_id}/reject")
def reject(action_id: uuid.UUID, request: ApprovalRequest, x_approval_token: str | None = Header(default=None)):
    return decide(action_id, request, "rejected", x_approval_token)

@app.post("/actions/{action_id}/dry-run")
def dry_run(action_id: uuid.UUID):
    row = get_action(action_id)
    executor_ready = EXECUTOR_ENABLED and bool(EXECUTOR_URL) and len(EXECUTOR_SHARED_SECRET.encode()) >= 32
    executor_state = "enabled" if executor_ready else "disabled"
    audit(action_id, "dry_run_completed", "safety_gate", {"would_mutate": False, "executor": executor_state, "proposal_sha256": row["proposal_sha256"]})
    return {"action_request_id": action_id, "decision": row["decision"], "risk": row["risk"], "would_mutate": False, "executed": False, "executor": executor_state}

def require_execution_token(token: str | None):
    if len(EXECUTION_TOKEN.encode()) < 32:
        raise HTTPException(503, "Operator execution authentication is not configured")
    if not token or not secrets.compare_digest(token, EXECUTION_TOKEN):
        raise HTTPException(401 if not token else 403, "Operator execution token is invalid")

@app.post("/actions/{action_id}/execute")
def execute_action(action_id: uuid.UUID, x_execution_token: str | None = Header(default=None)):
    require_execution_token(x_execution_token)
    if not EXECUTOR_ENABLED or not EXECUTOR_URL or len(EXECUTOR_SHARED_SECRET.encode()) < 32:
        raise HTTPException(503, "Execution is unavailable: isolated Executor is disabled or not securely configured")
    row = get_action(action_id)
    current = now()
    if row["decision"] == "REQUIRE_APPROVAL":
        if row["status"] != "approved":
            raise HTTPException(409, "A current human approval is required")
        if not row["approval_expires_at"] or current >= row["approval_expires_at"]:
            with conn() as c:
                c.execute("UPDATE agentshield_action_requests SET status='expired',updated_at=%s WHERE id=%s AND status='approved'", (current, action_id))
            audit(action_id, "approval_expired", "safety_gate", {"at_execution": True})
            raise HTTPException(409, "Approval expired before execution")
    elif row["decision"] != "ALLOW" or row["status"] != "validated":
        raise HTTPException(409, "Action is not in an executable Safety Gate state")

    prior_status = row["status"]
    # A conditional write is the one-time execution claim. Concurrent requests
    # cannot both obtain a capability for the same action.
    with conn() as c:
        claimed = c.execute("""UPDATE agentshield_action_requests SET status='executing',updated_at=%s
          WHERE id=%s AND ((decision='ALLOW' AND status='validated') OR
          (decision='REQUIRE_APPROVAL' AND status='approved' AND approval_expires_at > %s)) RETURNING *""",
          (current, action_id, current)).fetchone()
    if not claimed:
        raise HTTPException(409, "Action was claimed or changed before execution")

    issued = now()
    grant = {
        "action_id": str(action_id),
        "proposal_sha256": row["proposal_sha256"],
        "action_type": row["action_type"],
        "parameters": row["parameters"],
        "decision": row["decision"],
        "action_status": prior_status,
        "approval_expires_at": row["approval_expires_at"].isoformat() if row["approval_expires_at"] else None,
        "issued_at": issued.isoformat(),
        "expires_at": min(issued + timedelta(seconds=30), row["approval_expires_at"]).isoformat() if row["approval_expires_at"] else (issued + timedelta(seconds=30)).isoformat(),
        "nonce": secrets.token_urlsafe(32),
    }
    signature = hmac.new(EXECUTOR_SHARED_SECRET.encode(), canonical(grant).encode(), hashlib.sha256).hexdigest()
    try:
        response = httpx.post(EXECUTOR_URL + "/execute", json=grant,
                              headers={"X-Gate-Signature": signature}, timeout=35, trust_env=False)
        if response.status_code >= 400:
            body = response.json()
            detail = body.get("detail") if isinstance(body, dict) else None
            if isinstance(detail, dict) and detail.get("action_id") == str(action_id):
                result = detail
            else:
                response.raise_for_status()
        else:
            result = response.json()
    except Exception as exc:
        with conn() as c:
            c.execute("UPDATE agentshield_action_requests SET status='execution_failed',updated_at=%s WHERE id=%s AND status='executing'", (now(), action_id))
        audit(action_id, "execution_failed", "safety_gate", {"error": type(exc).__name__, "proposal_sha256": row["proposal_sha256"]})
        raise HTTPException(502, "Executor did not confirm an accepted result") from exc

    final_status = "executed" if result.get("status") == "executed" and result.get("executed") is True else "execution_failed"
    with conn() as c:
        c.execute("UPDATE agentshield_action_requests SET status=%s,dry_run=FALSE,updated_at=%s WHERE id=%s AND status='executing'", (final_status, now(), action_id))
    audit(action_id, "execution_" + final_status, "safety_gate", {"proposal_sha256": row["proposal_sha256"], "executor_result": result})
    if final_status != "executed":
        raise HTTPException(502, detail={"message": "Executor did not accept the action", "result": result})

    verification = {"status": "unavailable", "reason": "independent verifier is not configured"}
    if VERIFIER_URL and len(VERIFIER_TOKEN.encode()) >= 32:
        try:
            with conn() as c:
                incident = c.execute("SELECT state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (row["incident_id"],)).fetchone()
                if not incident:
                    raise RuntimeError("incident record is missing")
                incident_state = incident["state"] or "DETECTED"
                if incident_state not in {"GATED", "APPROVAL_PENDING", "EXECUTING"}:
                    raise RuntimeError("incident is not in a gated execution state")
                if incident_state != "EXECUTING":
                    c.execute("UPDATE agentshield_incidents SET state='EXECUTING',last_seen_at=%s WHERE id=%s", (now(), row["incident_id"]))
                    c.execute("INSERT INTO agentshield_incident_transitions VALUES (%s,%s,%s,'EXECUTING','executor_action_accepted',%s)", (uuid.uuid4(), row["incident_id"], incident_state, now()))
            response = httpx.post(VERIFIER_URL + "/verify", json={"incident_id": str(row["incident_id"]), "execution_id": str(action_id), "target": "api"}, headers={"X-Verifier-Token": VERIFIER_TOKEN}, timeout=40, trust_env=False)
            response.raise_for_status()
            verification = response.json()
        except Exception as exc:
            verification = {"status": "unavailable", "reason": type(exc).__name__}
            with conn() as c:
                incident = c.execute("SELECT state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (row["incident_id"],)).fetchone()
                if incident and incident["state"] in {"EXECUTING", "VERIFYING"}:
                    previous_state = incident["state"]
                    c.execute("UPDATE agentshield_incidents SET state='ESCALATED',status='open',last_seen_at=%s WHERE id=%s", (now(), row["incident_id"]))
                    c.execute("INSERT INTO agentshield_incident_transitions VALUES (%s,%s,%s,'ESCALATED','independent_verification_unavailable',%s)", (uuid.uuid4(), row["incident_id"], previous_state, now()))
            audit(action_id, "verification_unavailable", "safety_gate", verification)
    result["verification"] = verification
    return result

@app.get("/actions/{action_id}/audit")
def audit_log(action_id: uuid.UUID):
    get_action(action_id)
    with conn() as c:
        return c.execute("SELECT * FROM agentshield_action_audit WHERE action_request_id=%s ORDER BY created_at", (action_id,)).fetchall()
