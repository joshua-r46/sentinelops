"""Phase 6.2 recovery eligibility and authorization policy only.

This service does not restore, restart, or execute infrastructure actions.
Snapshot and audit HMAC keys are read from a separate mounted secret file.
"""
import hashlib
import hmac
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

import snapshots

DB = os.getenv("DATABASE_URL", "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack")
OPERATOR_TOKENS = json.loads(os.getenv("RECOVERY_OPERATOR_TOKENS_JSON", "{}"))
APPROVER_TOKENS = json.loads(os.getenv("RECOVERY_APPROVER_TOKENS_JSON", "{}"))
MAX_SNAPSHOT_AGE_SECONDS = max(60, int(os.getenv("RECOVERY_MAX_SNAPSHOT_AGE_SECONDS", "86400")))
MAX_ATTEMPTS_PER_INCIDENT = max(1, int(os.getenv("RECOVERY_MAX_ATTEMPTS_PER_INCIDENT", "3")))
AUDIT_LOCK_ID = 721462032


def conn():
    return psycopg.connect(DB, row_factory=dict_row)


def now():
    return datetime.now(timezone.utc)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def audit_key() -> bytes:
    master = snapshots.integrity_key()
    return hmac.new(master, b"agentshield-recovery-audit-v1", hashlib.sha256).digest()


def audit_body(row: dict):
    return {"event_id": str(row["event_id"]), "incident_id": str(row["incident_id"]) if row["incident_id"] else None,
            "execution_id": str(row["execution_id"]) if row["execution_id"] else None,
            "snapshot_id": str(row["snapshot_id"]) if row["snapshot_id"] else None,
            "recovery_request_id": str(row["recovery_request_id"]) if row["recovery_request_id"] else None,
            "event_type": row["event_type"], "actor": row["actor"], "details": row["details"],
            "created_at": row["created_at"].isoformat(), "previous_hmac": row["previous_hmac"]}


def append_audit(c, event_type: str, actor: str, details: dict,
                 incident_id=None, execution_id=None, snapshot_id=None, recovery_request_id=None):
    c.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_ID,))
    previous = c.execute("SELECT event_hmac_sha256 FROM agentshield_recovery_audit ORDER BY sequence_id DESC LIMIT 1").fetchone()
    previous_hmac = previous["event_hmac_sha256"] if previous else None
    event = {"event_id": uuid.uuid4(), "incident_id": incident_id, "execution_id": execution_id,
             "snapshot_id": snapshot_id, "recovery_request_id": recovery_request_id,
             "event_type": event_type, "actor": actor, "details": details, "created_at": now(),
             "previous_hmac": previous_hmac}
    signature = hmac.new(audit_key(), canonical(audit_body(event)).encode(), hashlib.sha256).hexdigest()
    c.execute("""INSERT INTO agentshield_recovery_audit
      (event_id,incident_id,execution_id,snapshot_id,recovery_request_id,event_type,actor,details,created_at,previous_hmac,event_hmac_sha256)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
      (event["event_id"], incident_id, execution_id, snapshot_id, recovery_request_id,
       event_type, actor, Jsonb(details), event["created_at"], previous_hmac, signature))
    c.execute("""INSERT INTO agentshield_action_audit
      (id,action_request_id,event_type,actor,details,created_at) VALUES (%s,%s,%s,%s,%s,%s)""",
      (uuid.uuid4(), execution_id, event_type, actor,
       Jsonb({**details, "recovery_audit_event_id": str(event["event_id"]), "event_hmac_sha256": signature}), event["created_at"]))
    return event["event_id"]


def verify_audit_rows(rows: list[dict], key: bytes):
    previous_hmac = None
    for row in rows:
        if row["previous_hmac"] != previous_hmac:
            return False, row["sequence_id"]
        expected = hmac.new(key, canonical(audit_body(row)).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, row["event_hmac_sha256"]):
            return False, row["sequence_id"]
        previous_hmac = row["event_hmac_sha256"]
    return True, None


def init():
    audit_key()  # Fail closed: no policy service without an independently mounted key.
    with conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_recovery_requests (
          id UUID PRIMARY KEY, request_id UUID NOT NULL UNIQUE,
          incident_id UUID NOT NULL REFERENCES agentshield_incidents(id),
          source_execution_id UUID NOT NULL, snapshot_id UUID NOT NULL REFERENCES agentshield_snapshots(id),
          action_type TEXT NOT NULL, target TEXT NOT NULL, version TEXT NOT NULL,
          status TEXT NOT NULL, attempt_number INTEGER NOT NULL,
          requested_by TEXT NOT NULL, requested_at TIMESTAMPTZ NOT NULL,
          approved_by TEXT, approved_at TIMESTAMPTZ, approval_note TEXT)""")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS agentshield_recovery_snapshot_once ON agentshield_recovery_requests(snapshot_id)")
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_recovery_audit (
          sequence_id BIGSERIAL PRIMARY KEY, event_id UUID UNIQUE NOT NULL,
          incident_id UUID, execution_id UUID, snapshot_id UUID, recovery_request_id UUID,
          event_type TEXT NOT NULL, actor TEXT NOT NULL, details JSONB NOT NULL,
          created_at TIMESTAMPTZ NOT NULL, previous_hmac TEXT,
          event_hmac_sha256 TEXT NOT NULL)""")
        c.execute("""CREATE OR REPLACE FUNCTION agentshield_reject_recovery_audit_mutation()
          RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN RAISE EXCEPTION 'Recovery audit records are immutable'; END; $$""")
        c.execute("DROP TRIGGER IF EXISTS agentshield_recovery_audit_immutable ON agentshield_recovery_audit")
        c.execute("""CREATE TRIGGER agentshield_recovery_audit_immutable
          BEFORE UPDATE OR DELETE ON agentshield_recovery_audit
          FOR EACH ROW EXECUTE FUNCTION agentshield_reject_recovery_audit_mutation()""")


class RecoveryAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=80)
    version: str | None = Field(default=None, max_length=50)


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: uuid.UUID
    incident_id: uuid.UUID
    execution_id: uuid.UUID
    snapshot_id: uuid.UUID
    action: RecoveryAction | None = None


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=1, max_length=500)


def token_actor(token: str | None, configured: dict, label: str):
    import secrets
    if not token:
        raise HTTPException(401, f"{label} token is required")
    for actor, expected in configured.items():
        if isinstance(expected, str) and len(expected.encode()) >= 32 and secrets.compare_digest(token, expected):
            return actor
    raise HTTPException(403, f"{label} token is not authorized")


def verify_snapshot(row: dict):
    if snapshots.digest(row["content"]) != row["content_sha256"]:
        return False, "snapshot_sha256_mismatch"
    signature = row.get("integrity_hmac_sha256")
    if not signature:
        return False, "snapshot_external_signature_missing"
    expected = snapshots.sign_snapshot(row["id"], row["incident_id"], row["execution_id"],
                                       row["target"], row["captured_at"], row["content"],
                                       row["content_sha256"])
    if not hmac.compare_digest(expected, signature):
        return False, "snapshot_external_signature_invalid"
    return True, "verified"


def validate_eligibility(c, request: RecoveryRequest):
    incident = c.execute("SELECT state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (request.incident_id,)).fetchone()
    snapshot = c.execute("SELECT * FROM agentshield_snapshots WHERE id=%s FOR UPDATE", (request.snapshot_id,)).fetchone()
    if not incident:
        return "incident_not_found", None
    if not snapshot:
        return "snapshot_not_found", None
    if snapshot["incident_id"] != request.incident_id or snapshot["execution_id"] != request.execution_id:
        return "snapshot_incident_or_execution_mismatch", snapshot
    if snapshot["target"] != "api":
        return "unsupported_snapshot_target", snapshot
    valid, integrity_reason = verify_snapshot(snapshot)
    if not valid:
        return integrity_reason, snapshot
    age = (now() - snapshot["captured_at"]).total_seconds()
    if age < 0 or age > MAX_SNAPSHOT_AGE_SECONDS:
        return "snapshot_expired_or_from_future", snapshot
    if incident["state"] != "ESCALATED":
        return "incident_not_eligible_for_recovery", snapshot
    source_action = c.execute("SELECT status,decision,action_type,parameters FROM agentshield_action_requests WHERE id=%s AND incident_id=%s FOR UPDATE",
                              (request.execution_id, request.incident_id)).fetchone()
    if not source_action or source_action["status"] != "executed" or source_action["decision"] != "REQUIRE_APPROVAL" or source_action["action_type"] != "restart_service" or source_action["parameters"].get("target") != "api":
        return "source_execution_not_eligible", snapshot
    verification = c.execute("SELECT outcome FROM agentshield_verifications WHERE execution_id=%s AND incident_id=%s ORDER BY completed_at DESC LIMIT 1",
                             (request.execution_id, request.incident_id)).fetchone()
    if not verification or verification["outcome"] != "FAILED":
        return "independent_verification_failure_required", snapshot
    if request.action is None:
        return "recovery_action_required", snapshot
    if request.action.action_type != "restore_api_deployment" or request.action.target != "api":
        return "unsupported_recovery_action", snapshot
    snapshot_version = (snapshot["content"].get("configuration") or {}).get("version")
    if not snapshot_version or request.action.version != snapshot_version:
        return "recovery_version_must_match_snapshot", snapshot
    return None, snapshot


def audit_rejection(request: RecoveryRequest, actor: str, reason: str, event_type="recovery_request_rejected"):
    with conn() as c:
        append_audit(c, event_type, actor, {"request_id": str(request.request_id), "reason": reason,
                     "incident_id": str(request.incident_id), "execution_id": str(request.execution_id),
                     "snapshot_id": str(request.snapshot_id)}, request.incident_id,
                     request.execution_id, request.snapshot_id)


def request_recovery(request: RecoveryRequest, actor: str):
    denial = None
    request_row = None
    try:
        with conn() as c:
            denial, snapshot = validate_eligibility(c, request)
            if denial is None:
                duplicate = c.execute("SELECT id FROM agentshield_recovery_requests WHERE request_id=%s OR snapshot_id=%s OR source_execution_id=%s FOR UPDATE",
                                      (request.request_id, request.snapshot_id, request.execution_id)).fetchone()
                if duplicate:
                    denial = "duplicate_or_replay_recovery_request"
            if denial is None:
                active = c.execute("SELECT id FROM agentshield_recovery_requests WHERE incident_id=%s AND status IN ('pending_approval','authorized') FOR UPDATE",
                                   (request.incident_id,)).fetchone()
                if active:
                    denial = "recovery_attempt_already_active"
            if denial is None:
                count = c.execute("SELECT count(*) AS attempts FROM agentshield_recovery_requests WHERE incident_id=%s", (request.incident_id,)).fetchone()["attempts"]
                if count >= MAX_ATTEMPTS_PER_INCIDENT:
                    denial = "recovery_attempt_limit_reached"
            if denial:
                append_audit(c, "recovery_request_rejected", actor, {"request_id": str(request.request_id),
                             "reason": denial, "incident_id": str(request.incident_id),
                             "execution_id": str(request.execution_id), "snapshot_id": str(request.snapshot_id)},
                             request.incident_id, request.execution_id, request.snapshot_id)
            else:
                attempt = count + 1
                recovery_id = uuid.uuid4()
                requested_at = now()
                action = request.action
                request_row = c.execute("""INSERT INTO agentshield_recovery_requests
                  (id,request_id,incident_id,source_execution_id,snapshot_id,action_type,target,version,status,attempt_number,requested_by,requested_at)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'pending_approval',%s,%s,%s) RETURNING *""",
                  (recovery_id, request.request_id, request.incident_id, request.execution_id,
                   request.snapshot_id, action.action_type, action.target, action.version, attempt, actor, requested_at)).fetchone()
                append_audit(c, "recovery_request_pending_approval", actor,
                             {"attempt_number": attempt, "action_type": action.action_type,
                              "target": action.target, "version": action.version},
                             request.incident_id, request.execution_id, request.snapshot_id, recovery_id)
    except psycopg.errors.UniqueViolation:
        denial = "duplicate_or_replay_recovery_request"
    if denial:
        if denial == "duplicate_or_replay_recovery_request":
            audit_rejection(request, actor, denial)
        raise HTTPException(409, denial)
    return request_row


def approve_recovery(request_id: uuid.UUID, approval: ApprovalRequest, actor: str):
    denial = None
    result = None
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_recovery_requests WHERE id=%s FOR UPDATE", (request_id,)).fetchone()
        if not row:
            denial = "recovery_request_not_found"
        elif row["status"] != "pending_approval":
            denial = "recovery_request_already_decided"
        elif row["requested_by"] == actor:
            denial = "requester_cannot_approve_own_recovery"
        else:
            snapshot_row = c.execute("SELECT * FROM agentshield_snapshots WHERE id=%s FOR UPDATE", (row["snapshot_id"],)).fetchone()
            request_data = RecoveryRequest(request_id=row["request_id"], incident_id=row["incident_id"],
                execution_id=row["source_execution_id"], snapshot_id=row["snapshot_id"],
                action=RecoveryAction(action_type=row["action_type"], target=row["target"], version=row["version"]))
            eligibility, _ = validate_eligibility(c, request_data)
            if eligibility:
                denial = "approval_revalidation_failed:" + eligibility
            elif not snapshot_row:
                denial = "approval_snapshot_missing"
        if denial:
            if row and row["status"] == "pending_approval":
                c.execute("UPDATE agentshield_recovery_requests SET status='rejected' WHERE id=%s", (request_id,))
            append_audit(c, "recovery_approval_rejected", actor, {"reason": denial},
                         row["incident_id"] if row else None, row["source_execution_id"] if row else None,
                         row["snapshot_id"] if row else None, request_id)
        else:
            result = c.execute("UPDATE agentshield_recovery_requests SET status='authorized',approved_by=%s,approved_at=%s,approval_note=%s WHERE id=%s AND status='pending_approval' RETURNING *",
                               (actor, now(), approval.note, request_id)).fetchone()
            if not result:
                denial = "recovery_request_already_decided"
                append_audit(c, "recovery_approval_rejected", actor, {"reason": denial},
                             row["incident_id"], row["source_execution_id"], row["snapshot_id"], request_id)
            else:
                append_audit(c, "recovery_authorized", actor, {"approval_note": approval.note,
                             "status": "authorized_no_restoration_in_phase_6_2"}, row["incident_id"],
                             row["source_execution_id"], row["snapshot_id"], request_id)
    if denial:
        raise HTTPException(409, denial)
    return result


def audit_chain_status():
    with conn() as c:
        rows = c.execute("SELECT * FROM agentshield_recovery_audit ORDER BY sequence_id").fetchall()
    valid, invalid_sequence = verify_audit_rows(rows, audit_key())
    return {"valid": valid, "event_count": len(rows), "first_invalid_sequence": invalid_sequence}


@asynccontextmanager
async def lifespan(app):
    init()
    yield


app = FastAPI(title="AgentShield Recovery Policy", lifespan=lifespan)


def audit_auth_failure(request: RecoveryRequest, kind: str):
    audit_rejection(request, "unauthenticated", kind, "recovery_authorization_rejected")


@app.get("/health")
def health():
    return {"service": "agentshield-recovery-policy", "status": "healthy", "restoration_enabled": False}


@app.post("/recovery/requests", status_code=201)
def create_request(request: RecoveryRequest, x_recovery_token: str | None = Header(default=None)):
    try:
        actor = token_actor(x_recovery_token, OPERATOR_TOKENS, "Recovery operator")
    except HTTPException as exc:
        audit_auth_failure(request, "operator_token_missing" if exc.status_code == 401 else "operator_token_invalid")
        raise
    return request_recovery(request, actor)


@app.post("/recovery/requests/{request_id}/approve")
def approve(request_id: uuid.UUID, approval: ApprovalRequest,
            x_recovery_approval_token: str | None = Header(default=None)):
    try:
        actor = token_actor(x_recovery_approval_token, APPROVER_TOKENS, "Recovery approver")
    except HTTPException as exc:
        with conn() as c:
            row = c.execute("SELECT * FROM agentshield_recovery_requests WHERE id=%s", (request_id,)).fetchone()
            append_audit(c, "recovery_authorization_rejected", "unauthenticated",
                         {"reason": "approver_token_missing" if exc.status_code == 401 else "approver_token_invalid",
                          "request_id": str(request_id)}, row["incident_id"] if row else None,
                         row["source_execution_id"] if row else None, row["snapshot_id"] if row else None, request_id)
        raise
    return approve_recovery(request_id, approval, actor)


@app.get("/recovery/requests/{request_id}")
def read_request(request_id: uuid.UUID, x_recovery_token: str | None = Header(default=None)):
    try:
        token_actor(x_recovery_token, OPERATOR_TOKENS, "Recovery operator")
    except HTTPException:
        raise
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_recovery_requests WHERE id=%s", (request_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Recovery request not found")
    return row


@app.get("/audit/verify")
def verify_audit(x_recovery_token: str | None = Header(default=None)):
    token_actor(x_recovery_token, OPERATOR_TOKENS, "Recovery operator")
    return audit_chain_status()
