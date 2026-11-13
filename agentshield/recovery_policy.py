"""Phase 6 recovery authorization, restoration delegation, and verification gate.

Infrastructure changes are delegated to the separately authorized Executor;
this service has no Docker socket or general-purpose mutation interface.
Snapshot and audit HMAC keys are read from a separate mounted secret file.
"""
import hashlib
import hmac
import json
import os
import uuid
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
import httpx
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
RECOVERY_EXECUTOR_ENABLED = os.getenv("RECOVERY_EXECUTOR_ENABLED", "false").lower() == "true"
RECOVERY_EXECUTOR_URL = os.getenv("RECOVERY_EXECUTOR_URL", "http://agentshield-executor:8004").rstrip("/")
RECOVERY_EXECUTOR_SHARED_SECRET = os.getenv("RECOVERY_EXECUTOR_SHARED_SECRET", "")
RECOVERY_VERIFIER_URL = os.getenv("RECOVERY_VERIFIER_URL", "http://agentshield-independent-verifier:8005").rstrip("/")
RECOVERY_VERIFIER_TOKEN = os.getenv("RECOVERY_VERIFIER_TOKEN", "")
RECOVERY_VERIFIER_TIMEOUT_SECONDS = max(30, min(600, int(os.getenv("RECOVERY_VERIFIER_TIMEOUT_SECONDS", "360"))))
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
    source_parameters = source_action["parameters"] if source_action else {}
    source_targets_api = source_parameters.get("target", source_parameters.get("service")) == "api"
    if not source_action or source_action["status"] != "executed" or source_action["decision"] != "REQUIRE_APPROVAL" or source_action["action_type"] not in {"restart_service", "rollback_deployment"} or not source_targets_api:
        return "source_execution_not_eligible", snapshot
    verification = c.execute("SELECT outcome FROM agentshield_verifications WHERE execution_id=%s AND incident_id=%s ORDER BY completed_at DESC LIMIT 1",
                             (request.execution_id, request.incident_id)).fetchone()
    if not verification or verification["outcome"] != "FAILED":
        return "independent_verification_failure_required", snapshot
    if request.action is None:
        return "recovery_action_required", snapshot
    if request.action.action_type != "rollback_deployment" or request.action.target != "api" or request.action.version not in {"v1", "v2", "v2-bad"}:
        return "unsupported_recovery_action", snapshot
    snapshot_version = (snapshot["content"].get("deployment") or {}).get("version")
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
                             "status": "authorized_for_phase_6_3"}, row["incident_id"],
                             row["source_execution_id"], row["snapshot_id"], request_id)
    if denial:
        raise HTTPException(409, denial)
    return result


def execute_authorized_recovery(request_id: uuid.UUID, actor: str):
    if not RECOVERY_EXECUTOR_ENABLED:
        return {"status": "authorized", "execution_enabled": False, "incident_resolved": False}
    if len(RECOVERY_EXECUTOR_SHARED_SECRET.encode()) < 32:
        raise HTTPException(503, "Recovery Executor authorization is not configured")
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_recovery_requests WHERE id=%s FOR UPDATE", (request_id,)).fetchone()
        if not row or row["status"] != "authorized":
            raise HTTPException(409, "Recovery request is not authorized for execution")
        snapshot = c.execute("SELECT * FROM agentshield_snapshots WHERE id=%s", (row["snapshot_id"],)).fetchone()
        if not snapshot:
            append_audit(c, "recovery_execution_rejected", actor, {"reason": "authorized_snapshot_missing"},
                         row["incident_id"], row["source_execution_id"], row["snapshot_id"], request_id)
            c.commit()
            raise HTTPException(409, "Authorized deployment snapshot is unavailable")
        valid, reason = verify_snapshot(snapshot)
        if not valid:
            append_audit(c, "recovery_execution_rejected", actor, {"reason": reason}, row["incident_id"],
                         row["source_execution_id"], row["snapshot_id"], request_id)
            c.commit()
            raise HTTPException(409, "Snapshot failed execution-time integrity validation")
        c.execute("UPDATE agentshield_recovery_requests SET status='executing' WHERE id=%s AND status='authorized'", (request_id,))
        envelope = {"snapshot_id": str(snapshot["id"]), "incident_id": str(snapshot["incident_id"]),
                    "execution_id": str(snapshot["execution_id"]), "target": snapshot["target"],
                    "captured_at": snapshot["captured_at"].isoformat(), "content": snapshot["content"],
                    "content_sha256": snapshot["content_sha256"],
                    "integrity_hmac_sha256": snapshot["integrity_hmac_sha256"]}
        now_value = now()
        grant = {"action_id": str(request_id),
                 "proposal_sha256": hashlib.sha256(canonical({"service": "api", "version": row["version"],
                                                               "snapshot_id": str(row["snapshot_id"])}).encode()).hexdigest(),
                 "action_type": "rollback_deployment", "parameters": {"service": "api", "version": row["version"]},
                 "decision": "REQUIRE_APPROVAL", "action_status": "approved",
                 "approval_expires_at": (now_value + timedelta(minutes=1)).isoformat(),
                 "issued_at": now_value.isoformat(), "expires_at": (now_value + timedelta(seconds=55)).isoformat(),
                 "nonce": secrets.token_hex(32), "snapshot_envelope": envelope}
        signature = hmac.new(RECOVERY_EXECUTOR_SHARED_SECRET.encode(), canonical(grant).encode(), hashlib.sha256).hexdigest()
        append_audit(c, "recovery_execution_started", actor, {"version": row["version"],
                     "action_type": "rollback_deployment"}, row["incident_id"], row["source_execution_id"],
                     row["snapshot_id"], request_id)
    try:
        response = httpx.post(RECOVERY_EXECUTOR_URL + "/execute", json=grant,
            headers={"X-Gate-Signature": signature}, timeout=55, trust_env=False)
        if response.status_code != 200:
            try:
                error_body = response.json()
                failure = error_body.get("detail", {}) if isinstance(error_body, dict) else {}
            except ValueError:
                failure = {}
            raise RuntimeError(json.dumps({"executor_rejected": True,
                                           "compensation": failure.get("compensation"),
                                           "error": failure.get("error", "executor_rejected")}))
        result = response.json()
        deployment_result = result.get("deployment", {})
        expected_deployment = snapshot["content"].get("deployment", {})
        if (result.get("executed") is not True or result.get("phase6_4_required") is not True
                or result.get("action_id") != str(request_id) or result.get("target") != "api"
                or deployment_result.get("version") != row["version"]
                or deployment_result.get("image_digest") != expected_deployment.get("image_digest")
                or deployment_result.get("config_revision") != expected_deployment.get("config_revision")
                or deployment_result.get("resource_limits") != expected_deployment.get("resource_limits")):
            raise RuntimeError("executor_result_invalid")
    except Exception as exc:
        compensation = None
        error_type = type(exc).__name__
        try:
            failure_detail = json.loads(str(exc))
            if failure_detail.get("executor_rejected"):
                compensation = failure_detail.get("compensation")
                error_type = failure_detail.get("error", error_type)
        except (ValueError, TypeError):
            pass
        with conn() as c:
            c.execute("UPDATE agentshield_recovery_requests SET status='execution_failed' WHERE id=%s AND status='executing'", (request_id,))
            append_audit(c, "recovery_execution_failed", actor, {"error_type": error_type,
                         "compensation": compensation},
                         row["incident_id"], row["source_execution_id"], row["snapshot_id"], request_id)
        return {"status": "execution_failed", "incident_resolved": False}
    with conn() as c:
        c.execute("UPDATE agentshield_recovery_requests SET status='verifying' WHERE id=%s AND status='executing'", (request_id,))
        deployment = result.get("deployment", {})
        append_audit(c, "recovery_execution_completed", actor,
                     {"version": row["version"], "image_digest": deployment.get("image_digest"),
                      "config_revision": deployment.get("config_revision"),
                      "incumbent_retained": deployment.get("incumbent_retained") is True,
                      "phase6_4_required": True, "executor_reported_success": True}, row["incident_id"], row["source_execution_id"],
                     row["snapshot_id"], request_id)
    return verify_restored_deployment(request_id, actor, row, snapshot, result)


def preflight_independent_verifier():
    """Fail before restoration if the independent verification service is unavailable."""
    if len(RECOVERY_VERIFIER_TOKEN.encode()) < 32:
        raise HTTPException(503, "Independent recovery verifier authorization is not configured")
    try:
        response = httpx.get(RECOVERY_VERIFIER_URL + "/health", timeout=3, trust_env=False)
        status = response.status_code
        identity = response.json() if status == 200 else {}
    except (httpx.HTTPError, ValueError):
        raise HTTPException(503, "Independent recovery verifier is unavailable")
    if (status != 200 or not isinstance(identity, dict)
            or identity.get("service") != "agentshield-independent-verifier"
            or identity.get("status") != "healthy"
            or identity.get("docker_access") != "none"
            or identity.get("recovery_verification_available") is not True):
        raise HTTPException(503, "Independent recovery verifier preflight failed")


def verify_restored_deployment(request_id: uuid.UUID, actor: str, recovery_row: dict,
                               snapshot: dict, executor_result: dict):
    """Ask the isolated verifier to prove recovery; executor output is not proof."""
    expected = snapshot.get("content", {}).get("deployment", {})
    payload = {
        "incident_id": str(recovery_row["incident_id"]),
        "recovery_request_id": str(request_id),
        "target": "api",
        "expected_version": recovery_row["version"],
        "expected_image_digest": expected.get("image_digest"),
        "expected_config_revision": expected.get("config_revision"),
        "expected_resource_limits": expected.get("resource_limits"),
    }
    outcome, reason, verification = "INCONCLUSIVE", "verifier_unavailable_or_invalid_response", {}
    try:
        response = httpx.post(RECOVERY_VERIFIER_URL + "/verify-recovery", json=payload,
                              headers={"X-Verifier-Token": RECOVERY_VERIFIER_TOKEN},
                              timeout=RECOVERY_VERIFIER_TIMEOUT_SECONDS, trust_env=False)
        if response.status_code == 200:
            verification = response.json()
            if not isinstance(verification, dict):
                verification = {}
                outcome, reason = "INCONCLUSIVE", "verifier_response_not_object"
            elif (str(verification.get("incident_id")) != str(recovery_row["incident_id"])
                    or str(verification.get("verification_id")) != str(request_id)):
                outcome, reason = "INCONCLUSIVE", "verifier_response_identity_mismatch"
            elif not _has_verification_evidence(verification):
                outcome, reason = "INCONCLUSIVE", "verifier_response_evidence_missing_or_invalid"
            elif verification.get("outcome") == "PASSED" and verification.get("incident_state") == "RESOLVED":
                outcome, reason = "PASSED", str(verification.get("reason", "all_recovery_checks_passed"))
            elif verification.get("outcome") == "FAILED" and verification.get("incident_state") == "ESCALATED":
                outcome, reason = "FAILED", str(verification.get("reason", "recovery_verification_failed"))
            elif verification.get("outcome") == "INCONCLUSIVE" and verification.get("incident_state") == "ESCALATED":
                outcome, reason = "INCONCLUSIVE", str(verification.get("reason", "recovery_verification_inconclusive"))
            else:
                outcome, reason = "INCONCLUSIVE", "verifier_response_outcome_state_mismatch"
    except (httpx.HTTPError, ValueError, TypeError):
        pass

    status = {"PASSED": "verified", "FAILED": "verification_failed",
              "INCONCLUSIVE": "verification_inconclusive"}[outcome]
    with conn() as c:
        c.execute("UPDATE agentshield_recovery_requests SET status=%s WHERE id=%s AND status='verifying'",
                  (status, request_id))
        append_audit(c, "recovery_independent_verification_" + outcome.lower(), actor,
                     {"outcome": outcome, "reason": reason,
                      "executor_reported_success": executor_result.get("executed") is True,
                      "verification_id": str(verification.get("verification_id", request_id)),
                      "evidence_id": str(verification.get("evidence_id")) if verification.get("evidence_id") else None,
                      "evidence_sha256": verification.get("evidence_sha256")},
                     recovery_row["incident_id"], recovery_row["source_execution_id"],
                     recovery_row["snapshot_id"], request_id)
    return {"status": status, "incident_resolved": outcome == "PASSED",
            "phase6_4_required": False, "verification_outcome": outcome,
            "verification_reason": reason}


def _has_verification_evidence(result: dict) -> bool:
    try:
        uuid.UUID(str(result["evidence_id"]))
        evidence_hash = result["evidence_sha256"]
        return (isinstance(evidence_hash, str) and len(evidence_hash) == 64
                and all(char in "0123456789abcdef" for char in evidence_hash)
                and isinstance(result.get("samples"), int) and result["samples"] >= 2)
    except (KeyError, TypeError, ValueError):
        return False


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
    enabled = RECOVERY_EXECUTOR_ENABLED and len(RECOVERY_EXECUTOR_SHARED_SECRET.encode()) >= 32
    return {"service": "agentshield-recovery-policy", "status": "healthy",
            "restoration_enabled": enabled, "production_execution_default": False}


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
    # Preflight before the approval state is committed. If verification is
    # unavailable, the request remains pending and no restoration can start.
    if RECOVERY_EXECUTOR_ENABLED:
        preflight_independent_verifier()
    approved = approve_recovery(request_id, approval, actor)
    if approved.get("status") == "authorized":
        return {**approved, "execution": execute_authorized_recovery(request_id, actor)}
    return approved


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
