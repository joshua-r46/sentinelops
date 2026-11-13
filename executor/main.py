import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import closing
from uuid import UUID
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

SECRET = os.getenv("EXECUTOR_SHARED_SECRET", "")
ENABLED = os.getenv("EXECUTOR_ENABLED", "false").lower() == "true"
STATE_DB = os.getenv("EXECUTOR_STATE_DB", "/tmp/agentshield-executor.sqlite3")
DOCKER_PROXY_URL = os.getenv("DOCKER_PROXY_URL", "http://docker-socket-proxy:2375").rstrip("/")
MAX_GRANT_SECONDS = 60
CLOCK_SKEW_SECONDS = 15
DOCKER_TARGET_CONTAINER = os.getenv("DOCKER_TARGET_CONTAINER", "shopstack-api")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", DOCKER_TARGET_CONTAINER):
    raise RuntimeError("DOCKER_TARGET_CONTAINER must be a single safe container name")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def timestamp(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


class Grant(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: UUID
    proposal_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    action_type: str = Field(min_length=1, max_length=80)
    parameters: dict[str, Any]
    decision: str
    action_status: str
    approval_expires_at: str | None = None
    issued_at: str
    expires_at: str
    nonce: str = Field(min_length=24, max_length=128)


class DockerProxy:
    """Narrow Docker adapter; all Docker access goes through the filtered proxy."""
    def __init__(self, base_url: str = DOCKER_PROXY_URL, client: httpx.Client | None = None,
                 container_name: str = DOCKER_TARGET_CONTAINER):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container_name):
            raise ValueError("Container name must be a single safe name")
        self.base_url = base_url
        self.container_name = container_name
        self.client = client or httpx.Client(timeout=8.0, trust_env=False)

    def inspect_api(self) -> dict[str, Any]:
        response = self.client.get(f"{self.base_url}/containers/{self.container_name}/json")
        if response.status_code != 200:
            raise RuntimeError("Could not inspect the approved service")
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("state"), dict):
            raise RuntimeError("Docker proxy returned an invalid inspection record")
        return data

    def restart_api(self) -> None:
        response = self.client.post(f"{self.base_url}/containers/{self.container_name}/restart")
        if response.status_code != 204:
            raise RuntimeError("Approved service restart was not accepted")


class Executor:
    def __init__(self, proxy: DockerProxy, db_path: str = STATE_DB, clock=time.time):
        self.proxy, self.db_path, self.clock = proxy, db_path, clock
        self._init_db()

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("""CREATE TABLE IF NOT EXISTS executions (
                action_id TEXT PRIMARY KEY,
                nonce TEXT NOT NULL UNIQUE,
                grant_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                snapshot_json TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""")

    def _validate(self, grant: Grant, signature: str):
        if not SECRET or len(SECRET.encode()) < 32:
            raise HTTPException(503, "Executor authorization is not configured")
        expected = hmac.new(SECRET.encode(), canonical(grant.model_dump(mode="json")), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise HTTPException(401, "Safety Gate authorization signature is invalid")
        current = self.clock()
        try:
            issued, expires = timestamp(grant.issued_at), timestamp(grant.expires_at)
            approval_expires = timestamp(grant.approval_expires_at) if grant.approval_expires_at else None
        except (ValueError, TypeError):
            raise HTTPException(401, "Authorization timestamps are invalid")
        if issued > current + CLOCK_SKEW_SECONDS or expires < current or expires <= issued or expires - issued > MAX_GRANT_SECONDS:
            raise HTTPException(401, "Safety Gate authorization is expired or outside its time window")
        if grant.decision == "REQUIRE_APPROVAL":
            if grant.action_status != "approved" or approval_expires is None or approval_expires < current or expires > approval_expires:
                raise HTTPException(403, "A current approval is required")
        elif grant.decision == "ALLOW":
            if grant.action_status != "validated":
                raise HTTPException(403, "Action is not in an executable Gate state")
        else:
            raise HTTPException(403, "Blocked actions cannot be executed")
        if grant.action_type != "restart_service" or grant.parameters != {"target": "api"}:
            raise HTTPException(422, "Executor supports only the typed api restart action")

    @staticmethod
    def _safe_snapshot(data: dict[str, Any]) -> dict[str, Any]:
        state = data.get("state") or {}
        config = data.get("config") or {}
        host = data.get("host_config") or {}
        return {
            "container_id": str(data.get("id", "")),
            "image_id": str(data.get("image", "")),
            "version": (config.get("labels") or {}).get("org.opencontainers.image.version"),
            "running_before": state.get("running") is True,
            "status_before": state.get("status"),
            "health_before": state.get("health"),
            "restart_policy": (host.get("restart_policy") or {}).get("name"),
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }

    def execute(self, grant: Grant, signature: str) -> dict[str, Any]:
        self._validate(grant, signature)
        grant_data = grant.model_dump(mode="json")
        grant_hash = hashlib.sha256(canonical(grant_data)).hexdigest()
        now_text = datetime.now(timezone.utc).isoformat()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO executions(action_id,nonce,grant_sha256,status,created_at,updated_at) VALUES(?,?,?,'started',?,?)",
                           (str(grant.action_id), grant.nonce, grant_hash, now_text, now_text))
            except sqlite3.IntegrityError:
                db.rollback()
                raise HTTPException(409, "Action or authorization nonce was already consumed")
            db.commit()
        finally:
            db.close()

        try:
            snapshot_data = self.proxy.inspect_api()
            snapshot = self._safe_snapshot(snapshot_data)
            if not snapshot["container_id"] or not snapshot["running_before"] or snapshot["status_before"] != "running":
                raise RuntimeError("Approved service is not running; restart was not attempted")
            with closing(self._connect()) as db:
                db.execute("UPDATE executions SET snapshot_json=?,updated_at=? WHERE action_id=?",
                           (json.dumps(snapshot, sort_keys=True), datetime.now(timezone.utc).isoformat(), str(grant.action_id)))
            self.proxy.restart_api()
            result = {"action_id": str(grant.action_id), "status": "executed", "executed": True,
                      "target": "api", "snapshot": snapshot}
            status = "executed"
        except Exception as exc:
            result = {"action_id": str(grant.action_id), "status": "failed", "executed": False,
                      "error": type(exc).__name__}
            status = "failed"
        with closing(self._connect()) as db:
            db.execute("UPDATE executions SET status=?,result_json=?,updated_at=? WHERE action_id=?",
                       (status, json.dumps(result, sort_keys=True), datetime.now(timezone.utc).isoformat(), str(grant.action_id)))
        if status != "executed":
            raise HTTPException(502, detail=result)
        return result



executor = Executor(DockerProxy())

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(title="AgentShield Isolated Executor", lifespan=lifespan)

@app.get("/health")
def health():
    return {"service": "agentshield-executor", "status": "healthy", "enabled": ENABLED,
            "supported_action": "restart_service:api", "docker_access": "filtered_proxy_only"}

@app.post("/execute")
def execute(grant: Grant, x_gate_signature: str | None = Header(default=None)):
    if not ENABLED:
        raise HTTPException(503, "Executor is disabled")
    if not x_gate_signature:
        raise HTTPException(401, "Safety Gate signature is required")
    return executor.execute(grant, x_gate_signature)
