import hashlib
import hmac
import importlib.util
import pathlib
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("phase4_gate", ROOT / "phase3policy" / "main.py")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class FakeCursor:
    def __init__(self, row=None):
        self.row = row
    def fetchone(self):
        return self.row


class FakeApprovalDB:
    def __init__(self):
        self.lock = threading.Lock()
        self.row = {"id": uuid.uuid4(), "decision": "REQUIRE_APPROVAL", "status": "pending_approval",
                    "proposal_sha256": "a" * 64,
                    "approval_expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)}
        self.approvals = []

    def connection(self):
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, db):
        self.db = db
    def __enter__(self):
        self.db.lock.acquire()
        self.before = dict(self.db.row)
        self.approvals_before = list(self.db.approvals)
        return self
    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.db.row = self.before
            self.db.approvals = self.approvals_before
        self.db.lock.release()
    def execute(self, query, params):
        if query.startswith("SELECT * FROM agentshield_action_requests"):
            return FakeCursor(dict(self.db.row))
        if query.startswith("UPDATE agentshield_action_requests SET status=%s"):
            status = params[0]
            if self.db.row["status"] != "pending_approval":
                return FakeCursor(None)
            self.db.row.update(status=status, updated_at=params[1])
            return FakeCursor(dict(self.db.row))
        if query.startswith("UPDATE agentshield_action_requests SET status='expired'"):
            self.db.row.update(status="expired", updated_at=params[0])
            return FakeCursor(dict(self.db.row))
        if query.startswith("INSERT INTO agentshield_action_approvals"):
            self.db.approvals.append(params)
            return FakeCursor()
        raise AssertionError("Unexpected SQL in approval test")


class FakeExecutionDB:
    def __init__(self):
        self.lock = threading.Lock()
        self.row = {"id": uuid.uuid4(), "decision": "REQUIRE_APPROVAL", "status": "approved",
                    "proposal_sha256": "b" * 64, "action_type": "restart_service",
                    "parameters": {"target": "api"},
                    "approval_expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)}

    def connection(self):
        return FakeExecutionConnection(self)


class FakeExecutionConnection:
    def __init__(self, db): self.db = db
    def __enter__(self): self.db.lock.acquire(); return self
    def __exit__(self, exc_type, exc, tb): self.db.lock.release()
    def execute(self, query, params):
        if query.startswith("SELECT * FROM agentshield_action_requests"):
            return FakeCursor(dict(self.db.row))
        if "SET status='executing'" in query:
            if self.db.row["status"] != "approved" or self.db.row["decision"] != "REQUIRE_APPROVAL":
                return FakeCursor(None)
            self.db.row.update(status="executing", updated_at=params[0])
            return FakeCursor(dict(self.db.row))
        if "SET status=%s,dry_run=FALSE" in query:
            if self.db.row["status"] == "executing":
                self.db.row.update(status=params[0], updated_at=params[1])
            return FakeCursor(dict(self.db.row))
        raise AssertionError("Unexpected SQL in execute test")


class GateExecutionAuthTests(unittest.TestCase):
    def test_execution_endpoint_requires_a_separate_operator_token(self):
        original = gate.EXECUTION_TOKEN
        gate.EXECUTION_TOKEN = "operator-token-with-at-least-32-characters"
        try:
            with self.assertRaises(gate.HTTPException) as missing:
                gate.require_execution_token(None)
            self.assertEqual(401, missing.exception.status_code)
            with self.assertRaises(gate.HTTPException) as incorrect:
                gate.require_execution_token("incorrect")
            self.assertEqual(403, incorrect.exception.status_code)
            gate.require_execution_token("operator-token-with-at-least-32-characters")
            gate.EXECUTION_TOKEN = "short"
            with self.assertRaises(gate.HTTPException) as unconfigured:
                gate.require_execution_token("short")
            self.assertEqual(503, unconfigured.exception.status_code)
        finally:
            gate.EXECUTION_TOKEN = original

    def test_gate_signs_one_time_executor_grant_only_after_operator_auth(self):
        db = FakeExecutionDB()
        old = (gate.conn, gate.audit, gate.EXECUTION_TOKEN, gate.EXECUTOR_ENABLED,
               gate.EXECUTOR_URL, gate.EXECUTOR_SHARED_SECRET, gate.httpx.post)
        posts, audits = [], []
        secret = "phase4-gate-shared-secret-32-bytes-minimum"
        def post(url, json, headers, timeout, trust_env):
            posts.append((url, json, headers, timeout, trust_env))
            expected = hmac.new(secret.encode(), gate.canonical(json).encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, headers["X-Gate-Signature"]):
                raise AssertionError("Gate signature did not match grant")
            class Response:
                status_code = 200
                def json(self): return {"action_id": json["action_id"], "status": "executed", "executed": True}
            return Response()
        gate.conn, gate.audit = db.connection, lambda *a, **kw: audits.append(a)
        gate.EXECUTION_TOKEN = "operator-token-with-at-least-32-characters"
        gate.EXECUTOR_ENABLED, gate.EXECUTOR_URL, gate.EXECUTOR_SHARED_SECRET = True, "http://executor", secret
        gate.httpx.post = post
        try:
            result = gate.execute_action(db.row["id"], gate.EXECUTION_TOKEN)
            self.assertTrue(result["executed"])
            self.assertEqual("executed", db.row["status"])
            with self.assertRaises(gate.HTTPException) as replay:
                gate.execute_action(db.row["id"], gate.EXECUTION_TOKEN)
            self.assertEqual(409, replay.exception.status_code)
            self.assertEqual(1, len(posts))
            with self.assertRaises(gate.HTTPException) as unauthenticated:
                gate.execute_action(uuid.uuid4(), "wrong-token")
            self.assertEqual(403, unauthenticated.exception.status_code)
        finally:
            (gate.conn, gate.audit, gate.EXECUTION_TOKEN, gate.EXECUTOR_ENABLED,
             gate.EXECUTOR_URL, gate.EXECUTOR_SHARED_SECRET, gate.httpx.post) = old

    def test_concurrent_approval_requests_commit_only_one_decision(self):
        db = FakeApprovalDB()
        original_conn, original_tokens, original_audit = gate.conn, gate.APPROVER_TOKENS, gate.audit
        gate.conn = db.connection
        gate.APPROVER_TOKENS = {"operator": "operator-secret"}
        gate.audit = lambda *args, **kwargs: None
        results = []
        barrier = threading.Barrier(2)
        def decide(decision):
            barrier.wait()
            try:
                gate.decide(db.row["id"], gate.ApprovalRequest(note="approved for test"), decision, "operator-secret")
                results.append("ok")
            except gate.HTTPException as exc:
                results.append(exc.status_code)
        threads = [threading.Thread(target=decide, args=(value,)) for value in ("approved", "rejected")]
        try:
            for thread in threads: thread.start()
            for thread in threads: thread.join()
        finally:
            gate.conn, gate.APPROVER_TOKENS, gate.audit = original_conn, original_tokens, original_audit
        self.assertCountEqual(["ok", 409], results)
        self.assertIn(db.row["status"], {"approved", "rejected"})
        self.assertEqual(1, len(db.approvals))


if __name__ == "__main__":
    unittest.main()
