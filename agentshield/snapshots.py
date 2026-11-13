"""Authorized, immutable snapshots of allowlisted ShopStack state.

This service reads fixed API/deployer endpoints and stores a digest-protected
snapshot in the AgentShield audit database. It has no Docker or shell access.
"""
import hashlib
import json
import os
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
TOKEN = os.getenv("SNAPSHOT_TOKEN", "")
API_URL = os.getenv("SNAPSHOT_API_URL", "http://api:8000").rstrip("/")
DEPLOYER_URL = os.getenv("SNAPSHOT_DEPLOYER_URL", "http://deployer:8001").rstrip("/")
MAX_DEPLOYMENTS = 100
SAFE_DEPLOYMENT_FIELDS = (
    "deployment_id", "service_name", "version", "previous_version", "change_type", "status",
    "created_at", "requested_at", "approved_at", "applied_at", "verified_at", "failed_at",
    "rolled_back_at",
)


def conn():
    return psycopg.connect(DB, row_factory=dict_row)


def now():
    return datetime.now(timezone.utc)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class SnapshotRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: uuid.UUID
    execution_id: uuid.UUID
    target: str = Field(pattern=r"^api$")


def init():
    with conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS agentshield_snapshots (
          id UUID PRIMARY KEY, incident_id UUID NOT NULL REFERENCES agentshield_incidents(id),
          execution_id UUID NOT NULL UNIQUE, target TEXT NOT NULL, captured_at TIMESTAMPTZ NOT NULL,
          content JSONB NOT NULL, content_sha256 TEXT NOT NULL)""")
        c.execute("""CREATE OR REPLACE FUNCTION agentshield_reject_snapshot_mutation()
          RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN RAISE EXCEPTION 'AgentShield snapshots are immutable'; END; $$""")
        c.execute("DROP TRIGGER IF EXISTS agentshield_snapshots_immutable ON agentshield_snapshots")
        c.execute("""CREATE TRIGGER agentshield_snapshots_immutable
          BEFORE UPDATE OR DELETE ON agentshield_snapshots
          FOR EACH ROW EXECUTE FUNCTION agentshield_reject_snapshot_mutation()""")


def authorize(token: str | None):
    import secrets
    if len(TOKEN.encode()) < 32:
        raise HTTPException(503, "Snapshot authorization is not configured")
    if not token or not secrets.compare_digest(token, TOKEN):
        raise HTTPException(401 if not token else 403, "Snapshot token is invalid")


async def read_snapshot_content():
    async with httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=False) as client:
        api_response = await client.get(API_URL + "/")
        api_response.raise_for_status()
        api = api_response.json()
        health_response = await client.get(API_URL + "/health")
        health_response.raise_for_status()
        health = health_response.json()
        deploy_response = await client.get(DEPLOYER_URL + "/deployments")
        deploy_response.raise_for_status()
        deployments = deploy_response.json()
    if not isinstance(api, dict) or not isinstance(health, dict) or not isinstance(deployments, list):
        raise HTTPException(502, "A supported ShopStack endpoint returned an invalid snapshot payload")
    projected = []
    for item in deployments[:MAX_DEPLOYMENTS]:
        if not isinstance(item, dict):
            continue
        projected.append({key: item.get(key) for key in SAFE_DEPLOYMENT_FIELDS if key in item})
    return {
        "configuration": {key: api[key] for key in ("application", "service", "version") if key in api},
        "runtime": {"status": health.get("status"), "dependencies": health.get("dependencies", {})},
        "deployment_state": {"entries": projected, "captured_count": len(projected),
                             "total_count": len(deployments), "truncated": len(deployments) > MAX_DEPLOYMENTS},
    }


async def create_snapshot(request: SnapshotRequest):
    captured = now()
    content = await read_snapshot_content()
    snapshot_id = uuid.uuid4()
    content_hash = digest(content)
    with conn() as c:
        incident = c.execute("SELECT state FROM agentshield_incidents WHERE id=%s FOR UPDATE", (request.incident_id,)).fetchone()
        if not incident:
            raise HTTPException(404, "Incident not found")
        if incident["state"] not in {"GATED", "APPROVAL_PENDING"}:
            raise HTTPException(409, "Snapshots are only captured before execution for a gated incident")
        action = c.execute("SELECT status,decision,action_type,parameters FROM agentshield_action_requests WHERE id=%s AND incident_id=%s FOR UPDATE",
                           (request.execution_id, request.incident_id)).fetchone()
        if not action or action["status"] != "approved" or action["decision"] != "REQUIRE_APPROVAL" or action["action_type"] != "restart_service" or action["parameters"].get("target") != "api":
            raise HTTPException(409, "Snapshot must bind to an approved, allowlisted API restart action")
        try:
            c.execute("INSERT INTO agentshield_snapshots VALUES (%s,%s,%s,%s,%s,%s,%s)",
                      (snapshot_id, request.incident_id, request.execution_id, request.target, captured,
                       Jsonb(content), content_hash))
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, "A pre-action snapshot already exists for this execution")
        c.execute("INSERT INTO agentshield_action_audit (id,action_request_id,event_type,actor,details,created_at) VALUES (%s,%s,'snapshot_created','snapshot_manager',%s,%s)",
                  (uuid.uuid4(), request.execution_id, Jsonb({"snapshot_id": str(snapshot_id),
                   "incident_id": str(request.incident_id), "execution_id": str(request.execution_id),
                   "content_sha256": content_hash}), captured))
    return {"snapshot_id": snapshot_id, "incident_id": request.incident_id,
            "execution_id": request.execution_id, "target": request.target,
            "captured_at": captured, "content_sha256": content_hash}


def get_snapshot(snapshot_id: uuid.UUID):
    corrupted = False
    with conn() as c:
        row = c.execute("SELECT * FROM agentshield_snapshots WHERE id=%s", (snapshot_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Snapshot not found")
        if digest(row["content"]) != row["content_sha256"]:
            c.execute("INSERT INTO agentshield_action_audit (id,action_request_id,event_type,actor,details,created_at) VALUES (%s,%s,'snapshot_integrity_failed','snapshot_manager',%s,%s)",
                      (uuid.uuid4(), row["execution_id"], Jsonb({"snapshot_id": str(snapshot_id),
                       "incident_id": str(row["incident_id"]), "execution_id": str(row["execution_id"])}), now()))
            corrupted = True
        else:
            c.execute("INSERT INTO agentshield_action_audit (id,action_request_id,event_type,actor,details,created_at) VALUES (%s,%s,'snapshot_accessed','snapshot_manager',%s,%s)",
                      (uuid.uuid4(), row["execution_id"], Jsonb({"snapshot_id": str(snapshot_id),
                       "incident_id": str(row["incident_id"]), "execution_id": str(row["execution_id"]),
                       "content_sha256": row["content_sha256"]}), now()))
    if corrupted:
        raise HTTPException(409, "Snapshot integrity verification failed")
    return row


@asynccontextmanager
async def lifespan(app):
    init()
    yield


app = FastAPI(title="AgentShield Snapshot Manager", lifespan=lifespan)


@app.get("/health")
def health():
    return {"service": "agentshield-snapshot-manager", "status": "healthy", "docker_access": "none"}


@app.post("/snapshots", status_code=201)
async def create(request: SnapshotRequest, x_snapshot_token: str | None = Header(default=None)):
    authorize(x_snapshot_token)
    return await create_snapshot(request)


@app.get("/snapshots/{snapshot_id}")
def retrieve(snapshot_id: uuid.UUID, x_snapshot_token: str | None = Header(default=None)):
    authorize(x_snapshot_token)
    row = get_snapshot(snapshot_id)
    return {"snapshot_id": row["id"], "incident_id": row["incident_id"],
            "execution_id": row["execution_id"], "target": row["target"],
            "captured_at": row["captured_at"], "content": row["content"],
            "content_sha256": row["content_sha256"], "integrity": "verified"}
