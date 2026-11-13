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
DOCKER_PROXY_TOKEN = os.getenv("DOCKER_PROXY_TOKEN", "")
SNAPSHOT_INTEGRITY_KEY_FILE = os.getenv("SNAPSHOT_INTEGRITY_KEY_FILE", "/run/secrets/snapshot_integrity_key")
DEPLOYMENT_CATALOG_FILE = os.getenv("DEPLOYMENT_CATALOG_FILE", "/etc/agentshield/deployment-catalog.json")
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
    snapshot_envelope: dict[str, Any] | None = None


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

    def restore_deployment(self, version: str) -> dict[str, Any]:
        if version not in {"v1", "v2", "v2-bad"}:
            raise RuntimeError("Deployment version is not allowlisted")
        if len(DOCKER_PROXY_TOKEN.encode()) < 32:
            raise RuntimeError("Restricted Docker proxy authorization is not configured")
        response = self.client.post(f"{self.base_url}/deployment/restore", json={"version": version},
                                    headers={"X-Executor-Token": DOCKER_PROXY_TOKEN}, timeout=45)
        if response.status_code != 200:
            try:
                error = response.json()
            except ValueError:
                error = {}
            raise DeploymentProxyError(error.get("error", "deployment_failed"),
                                       error.get("compensation") if error.get("compensation") in {"succeeded", "uncertain"} else None)
        data = response.json()
        if data.get("status") != "candidate_active" or data.get("incumbent_retained") is not True:
            raise RuntimeError("Restricted proxy returned an invalid restoration result")
        return data


class DeploymentProxyError(RuntimeError):
    def __init__(self, code: str, compensation: str | None = None):
        super().__init__(code)
        self.code = code
        self.compensation = compensation


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
        grant_data = grant.model_dump(mode="json")
        if grant.snapshot_envelope is None:
            grant_data.pop("snapshot_envelope", None)
        expected = hmac.new(SECRET.encode(), canonical(grant_data), hashlib.sha256).hexdigest()
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
        if grant.action_type == "restart_service":
            if grant.parameters != {"target": "api"} or grant.snapshot_envelope is not None:
                raise HTTPException(422, "Executor supports only the typed api restart action")
        elif grant.action_type == "rollback_deployment":
            if set(grant.parameters) != {"service", "version"} or grant.parameters.get("service") != "api" or grant.parameters.get("version") not in {"v1", "v2", "v2-bad"}:
                raise HTTPException(422, "Executor supports only rollback_deployment(api, allowlisted_version)")
            self._validate_snapshot_envelope(grant)
        else:
            raise HTTPException(422, "Executor action type is not allowlisted")

    @staticmethod
    def _validate_snapshot_envelope(grant: Grant):
        envelope = grant.snapshot_envelope
        required = {"snapshot_id", "incident_id", "execution_id", "target", "captured_at", "content",
                    "content_sha256", "integrity_hmac_sha256"}
        if not isinstance(envelope, dict) or set(envelope) != required or envelope.get("target") != "api":
            raise HTTPException(422, "Signed API deployment snapshot is required")
        content = envelope.get("content")
        deployment = content.get("deployment") if isinstance(content, dict) else None
        if not isinstance(deployment, dict):
            raise HTTPException(422, "Deployment identity is missing from the snapshot")
        version = grant.parameters["version"]
        if deployment.get("version") != version:
            raise HTTPException(403, "Requested version does not match the signed deployment snapshot")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(deployment.get("image_digest", ""))):
            raise HTTPException(403, "Snapshot image identity is invalid")
        if not isinstance(deployment.get("config_revision"), str) or not isinstance(deployment.get("resource_limits"), dict):
            raise HTTPException(403, "Snapshot configuration identity is invalid")
        try:
            with open(DEPLOYMENT_CATALOG_FILE, encoding="utf-8") as catalog_file:
                catalog = json.load(catalog_file)
            approved = catalog["versions"][version]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(503, "Read-only deployment catalog is unavailable") from exc
        if (deployment["image_digest"] != approved.get("image_digest")
                or deployment["config_revision"] != approved.get("profile", {}).get("config_revision")
                or deployment["resource_limits"] != approved.get("profile", {}).get("resources")):
            raise HTTPException(403, "Snapshot deployment identity does not match the approved catalog")
        expected_sha = hashlib.sha256(canonical(content)).hexdigest()
        if not hmac.compare_digest(expected_sha, str(envelope.get("content_sha256", ""))):
            raise HTTPException(403, "Snapshot content digest is invalid")
        try:
            with open(SNAPSHOT_INTEGRITY_KEY_FILE, "rb") as key_file:
                key = key_file.read().strip()
        except OSError as exc:
            raise HTTPException(503, "Snapshot integrity key is unavailable") from exc
        if len(key) < 32:
            raise HTTPException(503, "Snapshot integrity key is not configured")
        message = canonical({"snapshot_id": str(envelope["snapshot_id"]),
                            "incident_id": str(envelope["incident_id"]),
                            "execution_id": str(envelope["execution_id"]), "target": envelope["target"],
                            "captured_at": str(envelope["captured_at"]), "content": content,
                            "content_sha256": envelope["content_sha256"]})
        expected_hmac = hmac.new(key, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_hmac, str(envelope["integrity_hmac_sha256"])):
            raise HTTPException(403, "Snapshot HMAC verification failed")

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
        if grant.snapshot_envelope is None:
            grant_data.pop("snapshot_envelope", None)
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
            if grant.action_type == "rollback_deployment":
                envelope = grant.snapshot_envelope
                deployment = envelope["content"]["deployment"]
                snapshot = {"snapshot_id": str(envelope["snapshot_id"]), "version": deployment["version"],
                            "image_digest": deployment["image_digest"], "config_revision": deployment["config_revision"],
                            "resource_limits": deployment["resource_limits"]}
                with closing(self._connect()) as db:
                    db.execute("UPDATE executions SET snapshot_json=?,updated_at=? WHERE action_id=?",
                               (json.dumps(snapshot, sort_keys=True), datetime.now(timezone.utc).isoformat(), str(grant.action_id)))
                deployment_result = self.proxy.restore_deployment(grant.parameters["version"])
                result = {"action_id": str(grant.action_id), "status": "executed", "executed": True,
                          "target": "api", "deployment": deployment_result, "phase6_4_required": True}
            else:
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
            if isinstance(exc, DeploymentProxyError):
                result["error"] = exc.code
                if exc.compensation:
                    result["compensation"] = exc.compensation
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
