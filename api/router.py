"""Stable API endpoint with a single authenticated, in-memory upstream switch."""
import hashlib
import hmac
import json
import os
import re
import tempfile
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict

CONTROL_SECRET = os.getenv("ROUTER_CONTROL_SECRET", "")
INITIAL_VERSION = os.getenv("ROUTER_INITIAL_VERSION", "v1")
if INITIAL_VERSION not in {"v1", "v2", "v2-bad"}:
    raise RuntimeError("ROUTER_INITIAL_VERSION is not allowlisted")
CATALOG_FILE = os.getenv("DEPLOYMENT_CATALOG_FILE", "/etc/agentshield/deployment-catalog.json")
STATE_FILE = os.getenv("ROUTER_STATE_FILE", "/var/lib/agentshield/router-state.json")
with open(CATALOG_FILE, encoding="utf-8") as catalog_file:
    CATALOG = json.load(catalog_file)
CANDIDATE_RE = re.compile(r"^as-api-candidate-[a-f0-9]{32}$")


def read_active():
    try:
        with open(STATE_FILE, encoding="utf-8") as state_file:
            state = json.load(state_file)
        version, candidate_id = state.get("version"), state.get("candidate_id")
        target(version, candidate_id)
        return version, candidate_id
    except FileNotFoundError:
        return INITIAL_VERSION, None
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        raise RuntimeError("Router deployment state is invalid") from exc


ACTIVE = read_active()


def persist_active(version, candidate_id):
    directory = os.path.dirname(STATE_FILE) or "."
    os.makedirs(directory, mode=0o750, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".router-state-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as state_file:
            json.dump({"version": version, "candidate_id": candidate_id}, state_file, sort_keys=True)
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(temp_path, STATE_FILE)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def target(version: str, candidate_id: str | None) -> str:
    if version not in CATALOG["versions"]:
        raise ValueError("Unsupported API version")
    if candidate_id is None:
        return f"http://api-{version}:8000"
    if not CANDIDATE_RE.fullmatch(candidate_id):
        raise ValueError("Invalid candidate identity")
    return f"http://{candidate_id}:8000"


def signature_body(version, candidate_id):
    return json.dumps({"version": version, "candidate_id": candidate_id}, sort_keys=True, separators=(",", ":")).encode()


class SwitchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    candidate_id: str | None


@asynccontextmanager
async def lifespan(app):
    target(INITIAL_VERSION, None)
    yield


app = FastAPI(title="ShopStack Stable API Router", lifespan=lifespan)


@app.get("/health")
async def health():
    version, candidate_id = ACTIVE
    upstream = target(version, candidate_id)
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            response = await client.get(upstream + "/health")
        return Response(content=response.content, status_code=response.status_code,
                        media_type=response.headers.get("content-type", "application/json"))
    except httpx.HTTPError:
        raise HTTPException(503, "Active API upstream is unavailable")


@app.get("/__deployment")
def deployment_state():
    version, candidate_id = ACTIVE
    entry = CATALOG["versions"][version]
    return {"service": "api", "version": version, "image_digest": entry["image_digest"],
            "config_revision": entry["profile"]["config_revision"],
            "resource_limits": entry["profile"]["resources"],
            "candidate_id": candidate_id}


@app.post("/__control/switch")
def switch(request: SwitchRequest, x_router_signature: str | None = Header(default=None)):
    if len(CONTROL_SECRET.encode()) < 32:
        raise HTTPException(503, "Router switching is disabled")
    if not x_router_signature:
        raise HTTPException(401, "Router switch authentication required")
    try:
        target(request.version, request.candidate_id)
    except ValueError as exc:
        raise HTTPException(422, "Unsupported router target") from exc
    expected = hmac.new(CONTROL_SECRET.encode(), signature_body(request.version, request.candidate_id), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_router_signature):
        raise HTTPException(403, "Router switch authentication failed")
    try:
        persist_active(request.version, request.candidate_id)
    except OSError as exc:
        raise HTTPException(503, "Router deployment state could not be stored") from exc
    global ACTIVE
    ACTIVE = (request.version, request.candidate_id)
    return {"status": "switched", "version": request.version}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request):
    version, candidate_id = ACTIVE
    upstream = target(version, candidate_id)
    body = await request.body()
    headers = {k: v for k, v in request.headers.items() if k.lower() not in {"host", "connection", "content-length"}}
    try:
        async with httpx.AsyncClient(timeout=30, trust_env=False, follow_redirects=False) as client:
            response = await client.request(request.method, f"{upstream}/{path}", params=request.query_params,
                                            headers=headers, content=body)
    except httpx.HTTPError:
        raise HTTPException(502, "API upstream is unavailable")
    out_headers = {k: v for k, v in response.headers.items() if k.lower() not in {"content-length", "transfer-encoding", "connection"}}
    return Response(content=response.content, status_code=response.status_code, headers=out_headers)
