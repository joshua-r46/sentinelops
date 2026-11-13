"""Telegram notifications and restricted operator commands.

Telegram is an authenticated client of read-only AgentShield endpoints and the
existing Phase 3 approval API. It has no Docker, shell, Executor, or generic
infrastructure command interface.
"""
import asyncio
import json
import os
import re
import sqlite3
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_IDS = {item.strip() for item in os.getenv("TELEGRAM_ALLOWED_CHAT_IDS", "").split(",") if item.strip()}
ALLOWED_USER_IDS = {item.strip() for item in os.getenv("TELEGRAM_ALLOWED_USER_IDS", "").split(",")
                    if item.strip().isdigit() and int(item.strip()) > 0}
NOTIFY_IDS = CHAT_IDS or ALLOWED_USER_IDS
SERVICE_TOKEN = os.getenv("TELEGRAM_SERVICE_TOKEN", "")
APPROVER_TOKEN = os.getenv("TELEGRAM_APPROVER_TOKEN", "")
QUEUE_TOKEN = os.getenv("TELEGRAM_QUEUE_TOKEN", SERVICE_TOKEN)
STATUS_URL = os.getenv("TELEGRAM_STATUS_URL", "http://agentshield:8002/health").rstrip("/")
INCIDENTS_URL = os.getenv("TELEGRAM_INCIDENTS_URL", "http://agentshield:8002/incidents").rstrip("/")
POLICY_URL = os.getenv("TELEGRAM_POLICY_URL", "http://agentshield-policy:8003").rstrip("/")
POLLING = os.getenv("TELEGRAM_POLLING_ENABLED", "false").lower() == "true"
STATE_DB = os.getenv("TELEGRAM_STATE_DB", "./data/telegram-state.sqlite3")
OFFSET = 0  # compatibility observability; durable offset is the SQLite state row
POLL_TASK: asyncio.Task | None = None
SAFE_TEXT = re.compile(
    r"(?i)(bearer\s+|api[_-]?key[=:]\s*|token[=:]\s*|password[=:]\s*|secret[=:]\s*)[^\s,;]+"
)
SAFE_URL = re.compile(r"(?i)\b(?:https?|postgres(?:ql)?|redis)://[^\s,;]+")
SAFE_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
app = FastAPI(title="AgentShield Telegram Notifications and Approvals")


class Notice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=3000)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def safe_text(value: Any, max_length: int = 800) -> str:
    rendered = str(value)
    rendered = SAFE_URL.sub("[REDACTED_ENDPOINT]", rendered)
    rendered = SAFE_IPV4.sub("[REDACTED_IP]", rendered)
    rendered = SAFE_TEXT.sub(r"\1[REDACTED]", rendered)
    return rendered[:max_length]


@contextmanager
def state_connection():
    """Own and close every SQLite handle, including on errors and Windows."""
    path = Path(STATE_DB)
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_state():
    with state_connection() as db:
        db.execute("CREATE TABLE IF NOT EXISTS telegram_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT OR IGNORE INTO telegram_state(key,value) VALUES ('poll_offset','0')")
        db.execute("""CREATE TABLE IF NOT EXISTS telegram_updates (
          update_id INTEGER PRIMARY KEY, user_id TEXT NOT NULL, command TEXT NOT NULL,
          action_id TEXT, received_at TEXT NOT NULL, outcome TEXT NOT NULL,
          completed_at TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS telegram_audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, update_id INTEGER, user_id TEXT NOT NULL,
          event TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL)""")


def record_event(db, update_id: int | None, user_id: str, event: str, details: dict | None = None):
    db.execute("INSERT INTO telegram_audit(update_id,user_id,event,details,created_at) VALUES (?,?,?,?,?)",
               (update_id, user_id[:40], event[:80], json.dumps(details or {}, separators=(",", ":")), timestamp()))


def claim_update(update_id: int, user_id: str, command: str, action_id: str | None) -> bool:
    init_state()
    with state_connection() as db:
        cursor = db.execute("""INSERT OR IGNORE INTO telegram_updates
          (update_id,user_id,command,action_id,received_at,outcome) VALUES (?,?,?,?,?,'processing')""",
          (update_id, user_id[:40], command[:80], action_id, timestamp()))
        db.execute("UPDATE telegram_state SET value=CAST(MAX(CAST(value AS INTEGER),?) AS TEXT) WHERE key='poll_offset'",
                   (update_id + 1,))
        if cursor.rowcount == 0:
            record_event(db, update_id, user_id, "duplicate_update_rejected", {"command": command})
            return False
        record_event(db, update_id, user_id, "operator_update_received", {"command": command, "action_id": action_id})
        return True


def finish_update(update_id: int, user_id: str, outcome: str, event: str, details: dict | None = None):
    init_state()
    with state_connection() as db:
        db.execute("UPDATE telegram_updates SET outcome=?,completed_at=? WHERE update_id=? AND outcome='processing'",
                   (outcome[:80], timestamp(), update_id))
        record_event(db, update_id, user_id, event, details)


def read_offset() -> int:
    init_state()
    with state_connection() as db:
        row = db.execute("SELECT value FROM telegram_state WHERE key='poll_offset'").fetchone()
    return int(row["value"] if row else 0)


async def telegram_api(method: str, *, data: dict | None = None, params: dict | None = None):
    if not BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured")
    async with httpx.AsyncClient(timeout=35, trust_env=False) as client:
        response = await client.request("POST" if data is not None else "GET",
                                        f"https://api.telegram.org/bot{BOT_TOKEN}/{method}",
                                        json=data if data is not None else None,
                                        params=params, timeout=35 if method == "getUpdates" else 8)
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise ValueError("Telegram API rejected the request")
    return payload.get("result")


async def send(chat_id: str, text: str):
    if not BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured")
    await telegram_api("sendMessage", data={"chat_id": chat_id, "text": safe_text(text, 3500)})


async def internal_request(method: str, url: str, *, headers: dict | None = None, json_body: dict | None = None):
    async with httpx.AsyncClient(timeout=8, trust_env=False) as client:
        response = await client.request(method, url, headers=headers, json=json_body)
    return response


def parse_command(text: str) -> tuple[str, list[str]]:
    parts = (text or "").strip().split()
    if not parts or not parts[0].startswith("/"):
        return "", []
    command = parts[0].split("@", 1)[0].lower()
    return command, parts[1:]


def message_parts(update: dict):
    message = update.get("message")
    if not isinstance(message, dict):
        return None
    sender = message.get("from") if isinstance(message.get("from"), dict) else {}
    chat = message.get("chat") if isinstance(message.get("chat"), dict) else {}
    return {
        "user_id": str(sender.get("id", "")),
        "chat_id": str(chat.get("id", "")),
        "chat_type": chat.get("type"),
        "text": message.get("text", ""),
    }


async def get_status():
    response = await internal_request("GET", STATUS_URL)
    if not response.is_success:
        raise RuntimeError("status endpoint unavailable")
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("status response invalid")
    service = safe_text(data.get("service", "AgentShield"), 80)
    status = safe_text(data.get("status", "unknown"), 40)
    mode = safe_text(data.get("mode", ""), 80)
    return f"{service}: {status}" + (f" ({mode})" if mode else "")


async def show_incident(chat_id: str, incident_id: str):
    incident_id = str(uuid.UUID(incident_id))
    response = await internal_request("GET", INCIDENTS_URL + "/" + incident_id)
    if response.status_code == 404:
        return "Incident not found."
    if not response.is_success:
        raise RuntimeError("incident endpoint unavailable")
    item = response.json()
    return (f"Incident {incident_id}\nState: {safe_text(item.get('state', 'unknown'), 40)}\n"
            f"Status: {safe_text(item.get('status', 'unknown'), 40)}\n"
            f"Summary: {safe_text(item.get('summary', ''), 500)}")


async def list_incidents():
    """Return a bounded, redacted view of recent incidents for operators."""
    response = await internal_request("GET", INCIDENTS_URL)
    if response.status_code == 404:
        return "No incidents are currently available."
    if not response.is_success:
        raise RuntimeError("incident list endpoint unavailable")
    data = response.json()
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("items", data.get("incidents", []))
    else:
        raise ValueError("incident list response invalid")
    if not isinstance(items, list):
        raise ValueError("incident list response invalid")
    if not items:
        return "No incidents are currently reported."
    lines = ["Recent incidents:"]
    for item in items[:10]:
        if not isinstance(item, dict):
            continue
        incident_id = safe_text(item.get("id", "unknown"), 64)
        state = safe_text(item.get("state", "unknown"), 40)
        status = safe_text(item.get("status", "unknown"), 40)
        summary = safe_text(item.get("summary", ""), 240)
        lines.append(f"{incident_id} — {state}/{status}: {summary}")
    return "\n".join(lines) if len(lines) > 1 else "No incidents are currently reported."


async def list_approvals():
    if len(QUEUE_TOKEN.encode()) < 32:
        raise RuntimeError("approval queue access is not configured")
    response = await internal_request("GET", POLICY_URL + "/approvals/pending",
                                      headers={"X-Telegram-Queue-Token": QUEUE_TOKEN})
    if not response.is_success:
        raise RuntimeError("approval queue unavailable")
    data = response.json()
    items = data.get("items", []) if isinstance(data, dict) else []
    if not items:
        return "No pending approvals."
    lines = ["Pending approvals:"]
    for item in items[:10]:
        lines.append(f"{item['id']} — {safe_text(item.get('action_type'), 80)} on {safe_text(item.get('target'), 40)}; expires {safe_text(item.get('approval_expires_at'), 50)}")
    lines.append("Decide with /approve <id> or /deny <id>.")
    return "\n".join(lines)


async def decide_approval(decision: str, action_id: str, user_id: str):
    if decision not in {"approve", "deny"}:
        raise ValueError("unsupported approval decision")
    action_id = str(uuid.UUID(action_id))
    if len(APPROVER_TOKEN.encode()) < 32:
        raise RuntimeError("Telegram approval is not configured")
    endpoint = "approve" if decision == "approve" else "reject"
    response = await internal_request(
        "POST", f"{POLICY_URL}/actions/{action_id}/{endpoint}",
        headers={"X-Approval-Token": APPROVER_TOKEN},
        json_body={"note": f"Telegram {decision} by allowlisted user {user_id}"},
    )
    if response.status_code == 200:
        return f"Safety Gate recorded {decision} for action {action_id}."
    if response.status_code == 409:
        return "Safety Gate rejected this action because it is expired or already decided."
    if response.status_code in {401, 403}:
        raise RuntimeError("Safety Gate rejected Telegram approval authorization")
    raise RuntimeError("Safety Gate approval endpoint unavailable")


async def dispatch_update(update: dict):
    """Process one Telegram update with durable replay checks and audit records."""
    if not isinstance(update, dict) or not isinstance(update.get("update_id"), int):
        return "invalid_update"
    update_id = update["update_id"]
    fields = message_parts(update)
    if fields is None:
        return "ignored_update"
    user_id = fields["user_id"]
    chat_id = fields["chat_id"]
    command, args = parse_command(fields["text"])
    action_id = args[0] if command in {"/approve", "/deny"} and args else None
    if not claim_update(update_id, user_id, command or "unsupported", action_id):
        return "duplicate_update"
    if (not user_id.isdigit() or user_id not in ALLOWED_USER_IDS or fields["chat_type"] != "private"
            or chat_id != user_id):
        finish_update(update_id, user_id or "unknown", "rejected", "unauthorized_telegram_user")
        return "unauthorized"
    try:
        if command in {"/start", "/help"} and not args:
            reply = "AgentShield operator bot. Allowed commands: /help, /status, /incidents, /incident <id>, /approvals, /approve <id>, /deny <id>. Telegram cannot run infrastructure commands."
        elif command == "/status" and not args:
            reply = await get_status()
        elif command == "/incidents" and not args:
            reply = await list_incidents()
        elif command == "/incident" and len(args) == 1:
            reply = await show_incident(chat_id, args[0])
        elif command == "/approvals" and not args:
            reply = await list_approvals()
        elif command in {"/approve", "/deny"} and len(args) == 1:
            reply = await decide_approval(command[1:], args[0], user_id)
        else:
            reply = "Unsupported command. Use /help."
        await send(chat_id, reply)
        if command in {"/approve", "/deny"} and reply.startswith("Safety Gate recorded"):
            event, result_code = "approval_" + command[1:], "decided"
        elif command in {"/approve", "/deny"} and reply.startswith("Safety Gate rejected"):
            event, result_code = "approval_duplicate_or_expired_rejected", "rejected"
        else:
            event, result_code = "telegram_command_completed", "response_sent"
        finish_update(update_id, user_id, "completed", event,
                      {"command": command, "action_id": action_id, "result": result_code})
        return "completed"
    except (httpx.HTTPError, ValueError, RuntimeError, KeyError) as exc:
        error_type = type(exc).__name__
        finish_update(update_id, user_id, "failed", "telegram_command_failed",
                      {"command": command, "action_id": action_id, "error_type": error_type})
        try:
            await send(chat_id, "AgentShield could not complete that request. Check service status and retry if the approval is still pending.")
        except Exception:
            pass
        return "failed"


async def poll_once():
    global OFFSET
    offset = read_offset()
    updates = await telegram_api("getUpdates", params={"offset": offset, "timeout": 25,
                                                       "allowed_updates": '["message"]'})
    if not isinstance(updates, list):
        raise ValueError("Telegram update response invalid")
    for update in updates:
        if isinstance(update, dict) and isinstance(update.get("update_id"), int):
            OFFSET = max(OFFSET, update["update_id"] + 1)
        await dispatch_update(update)
    return len(updates)


async def poll():
    while True:
        if not BOT_TOKEN or not ALLOWED_USER_IDS:
            await asyncio.sleep(10)
            continue
        try:
            await poll_once()
        except Exception:
            await asyncio.sleep(5)
        await asyncio.sleep(1)


@app.get("/health")
def health():
    return {"status": "healthy", "configured": bool(BOT_TOKEN and NOTIFY_IDS and SERVICE_TOKEN),
            "operator_commands_configured": bool(BOT_TOKEN and ALLOWED_USER_IDS and SERVICE_TOKEN),
            "approval_configured": len(APPROVER_TOKEN.encode()) >= 32 and len(QUEUE_TOKEN.encode()) >= 32,
            "polling": POLLING}


@app.post("/notify")
async def notify(notice: Notice, authorization: str | None = Header(default=None)):
    import secrets
    if not BOT_TOKEN or not NOTIFY_IDS or len(SERVICE_TOKEN.encode()) < 32:
        raise HTTPException(503, "Telegram notifications are not configured")
    if not authorization or not secrets.compare_digest(authorization, f"Bearer {SERVICE_TOKEN}"):
        raise HTTPException(401, "Notification service authorization required")
    results = await asyncio.gather(*(send(chat, notice.text) for chat in NOTIFY_IDS), return_exceptions=True)
    return {"sent": sum(not isinstance(result, Exception) for result in results),
            "failed": sum(isinstance(result, Exception) for result in results)}


@asynccontextmanager
async def lifespan(app):
    global POLL_TASK
    init_state()
    if POLLING:
        POLL_TASK = asyncio.create_task(poll())
    yield
    if POLL_TASK:
        POLL_TASK.cancel()
        try:
            await POLL_TASK
        except asyncio.CancelledError:
            pass


app.router.lifespan_context = lifespan
