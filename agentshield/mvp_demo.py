"""Explicitly simulated, development-only AgentShield vertical slice.

The SQLite database is created in the system temporary directory and deleted
on shutdown. No ShopStack, Docker, or persistent database connection is used.
"""
import os
import sqlite3
import tempfile
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

if os.getenv("AGENTSHIELD_DEMO_MODE", "").lower() not in {"1", "true", "development", "test"}:
    raise RuntimeError("MVP demo is disabled; set AGENTSHIELD_DEMO_MODE=development explicitly")

DB_PATH = Path(tempfile.gettempdir()) / f"agentshield-demo-{uuid.uuid4().hex}.sqlite3"
STAMP = lambda: datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app):
    DB_PATH.unlink(missing_ok=True)
    with connect() as db:
        db.executescript("""
        CREATE TABLE incidents(id TEXT PRIMARY KEY, summary TEXT, state TEXT, created_at TEXT);
        CREATE TABLE events(id INTEGER PRIMARY KEY, incident_id TEXT, kind TEXT, payload TEXT, created_at TEXT);
        CREATE TABLE actions(id TEXT PRIMARY KEY, incident_id TEXT, status TEXT, approved_by TEXT, created_at TEXT);
        """)
    yield
    DB_PATH.unlink(missing_ok=True)


app = FastAPI(title="AgentShield Demonstration (Simulated)", lifespan=lifespan)


class Approval(BaseModel):
    approved: bool


@app.get("/")
def page():
    return FileResponse(Path(__file__).resolve().parents[1] / "agentshield-mvp-demo.html")


@app.get("/health")
def health():
    return {"status": "healthy", "mode": "explicit_simulation", "persistent_data": False}


@app.post("/demo/run")
def run_demo():
    incident_id = str(uuid.uuid4())
    evidence_id = str(uuid.uuid4())
    action_id = str(uuid.uuid4())
    with connect() as db:
        db.execute("INSERT INTO incidents VALUES(?,?,?,?)", (incident_id, "Simulated API error-rate alert", "DETECTED", STAMP()))
        db.execute("INSERT INTO events(incident_id,kind,payload,created_at) VALUES(?,?,?,?)",
                   (incident_id, "simulated_test_evidence", '{"evidence_id":"'+evidence_id+'","scenario":"bounded_api_error_rate","source":"demo_injector","simulated":true}', STAMP()))
        db.execute("INSERT INTO events(incident_id,kind,payload,created_at) VALUES(?,?,?,?)",
                   (incident_id, "diagnosis", '{"cause":"simulated_api_error_rate","confidence":0.91,"evidence_id":"'+evidence_id+'","simulated":true}', STAMP()))
        db.execute("INSERT INTO events(incident_id,kind,payload,created_at) VALUES(?,?,?,?)",
                   (incident_id, "safety_gate", '{"verdict":"REQUIRE_APPROVAL","risk":"R2","reason":"restart requires operator approval","simulated_policy_adapter":true}', STAMP()))
        db.execute("INSERT INTO actions VALUES(?,?,?,?,?)", (action_id, incident_id, "approval_pending", None, STAMP()))
        db.execute("UPDATE incidents SET state='APPROVAL_PENDING' WHERE id=?", (incident_id,))
    return {"incident_id": incident_id, "evidence_id": evidence_id, "action_id": action_id,
            "status": "approval_pending", "mode": "simulated_demo"}


@app.post("/demo/actions/{action_id}/approve")
def approve(action_id: str, request: Approval):
    with connect() as db:
        row = db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        if not row or row["status"] != "approval_pending":
            raise HTTPException(409, "Action is not awaiting approval")
        if not request.approved:
            db.execute("UPDATE actions SET status='denied' WHERE id=?", (action_id,))
            db.execute("UPDATE incidents SET state='ESCALATED' WHERE id=?", (row["incident_id"],))
            db.execute("INSERT INTO events(incident_id,kind,payload,created_at) VALUES(?,?,?,?)",
                       (row["incident_id"], "approval_denied", '{"result":"escalated"}', STAMP()))
            return {"status": "denied", "incident_state": "ESCALATED", "simulated": True}
        db.execute("UPDATE actions SET status='dry_run_executed',approved_by='demo_operator' WHERE id=?", (action_id,))
        db.execute("INSERT INTO events(incident_id,kind,payload,created_at) VALUES(?,?,?,?)",
                   (row["incident_id"], "dry_run_execution", '{"executed":false,"authorization":"approval_required","simulated":true}', STAMP()))
        db.execute("INSERT INTO events(incident_id,kind,payload,created_at) VALUES(?,?,?,?)",
                   (row["incident_id"], "simulated_verification", '{"outcome":"passed","source":"demo_verifier","simulated":true}', STAMP()))
        db.execute("UPDATE incidents SET state='RESOLVED_SIMULATED' WHERE id=?", (row["incident_id"],))
    return {"status": "dry_run_executed", "verification": "simulated_passed", "incident_state": "RESOLVED_SIMULATED", "simulated": True}


@app.get("/demo/overview")
def overview():
    with connect() as db:
        incidents = [dict(x) for x in db.execute("SELECT * FROM incidents ORDER BY created_at DESC")]
        events = [dict(x) for x in db.execute("SELECT * FROM events ORDER BY id")]
        actions = [dict(x) for x in db.execute("SELECT * FROM actions ORDER BY created_at DESC")]
    return {"mode": "SIMULATED DEMO — no infrastructure was changed", "incidents": incidents,
            "events": events, "actions": actions}
