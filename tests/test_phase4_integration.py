import hashlib
import hmac
import json
import os
import secrets
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import httpx
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


class Phase4IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = {
            "PHASE4_IT_MODE", "PHASE4_IT_DATABASE_URL", "PHASE4_IT_GATE_URL",
            "PHASE4_IT_EXECUTOR_URL", "PHASE4_IT_PROXY_URL", "PHASE4_IT_API_URL",
            "PHASE4_IT_TARGET_CONTAINER", "PHASE4_IT_EXECUTOR_SECRET",
            "PHASE4_IT_EXECUTION_TOKEN", "PHASE4_IT_APPROVER_TOKEN",
        }
        missing = required.difference(os.environ)
        if missing:
            raise unittest.SkipTest("Disposable Phase 4 integration environment is not configured")
        cls.mode = os.environ["PHASE4_IT_MODE"]
        cls.database_url = os.environ["PHASE4_IT_DATABASE_URL"]
        cls.gate_url = os.environ["PHASE4_IT_GATE_URL"].rstrip("/")
        cls.executor_url = os.environ["PHASE4_IT_EXECUTOR_URL"].rstrip("/")
        cls.proxy_url = os.environ["PHASE4_IT_PROXY_URL"].rstrip("/")
        cls.api_url = os.environ["PHASE4_IT_API_URL"].rstrip("/")
        cls.target = os.environ["PHASE4_IT_TARGET_CONTAINER"]
        cls.executor_secret = os.environ["PHASE4_IT_EXECUTOR_SECRET"]
        cls.execution_token = os.environ["PHASE4_IT_EXECUTION_TOKEN"]
        cls.approver_token = os.environ["PHASE4_IT_APPROVER_TOKEN"]
        dbinfo = psycopg.conninfo.conninfo_to_dict(cls.database_url)
        if dbinfo.get("dbname") != "shopstack_it" or not dbinfo.get("host", "").startswith("phase4-it-postgres-"):
            raise RuntimeError("Integration tests refuse non-disposable database endpoints")
        for value, prefix in (
            (cls.gate_url, "phase4-it-gate-"),
            (cls.executor_url, "phase4-it-executor-"),
            (cls.proxy_url, "phase4-it-proxy-"),
            (cls.api_url, "phase4-it-shopstack-api-"),
        ):
            if not (urlparse(value).hostname or "").startswith(prefix):
                raise RuntimeError("Integration tests refuse endpoints outside the disposable Phase 4 stack")
        if not cls.target.startswith("phase4-it-shopstack-api-"):
            raise RuntimeError("Integration target is not a disposable ShopStack API container")
        cls.client = httpx.Client(timeout=45, trust_env=False)
        cls.wait_for_services()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "client"):
            cls.client.close()

    @classmethod
    def wait_for_services(cls):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                gate = cls.client.get(cls.gate_url + "/health")
                executor = cls.client.get(cls.executor_url + "/health")
                proxy = cls.client.get(cls.proxy_url + "/containers/" + cls.target + "/json")
                if gate.status_code == 200 and executor.status_code == 200:
                    if cls.mode == "success":
                        api = cls.client.get(cls.api_url + "/")
                        if api.status_code == 200 and proxy.status_code == 200:
                            return
                    elif cls.mode == "docker_failure" and proxy.status_code == 404:
                        return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise RuntimeError("Disposable Phase 4 services did not become ready")

    def new_approved_action(self):
        incident_id = uuid.uuid4()
        evidence = {"source": "phase4-disposable-integration", "nonce": str(uuid.uuid4())}
        evidence_sha256 = hashlib.sha256(
            json.dumps(evidence, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        with psycopg.connect(self.database_url, row_factory=dict_row) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS agentshield_incidents (
                id UUID PRIMARY KEY, evidence JSONB NOT NULL)""")
            db.execute("INSERT INTO agentshield_incidents(id,evidence) VALUES (%s,%s)",
                       (incident_id, Jsonb(evidence)))
        proposal = self.client.post(self.gate_url + "/actions", json={
            "evidence": {"incident_id": str(incident_id), "evidence_sha256": evidence_sha256},
            "action": {"action_type": "restart_service", "target": "api", "parameters": {}},
        })
        self.assertEqual(201, proposal.status_code, proposal.text)
        body = proposal.json()
        self.assertEqual("REQUIRE_APPROVAL", body["decision"])
        self.assertEqual("pending_approval", body["status"])
        action_id = body["id"]
        execute_url = self.gate_url + f"/actions/{action_id}/execute"
        self.assertEqual(401, self.client.post(execute_url).status_code)
        self.assertEqual(403, self.client.post(
            execute_url, headers={"X-Execution-Token": "wrong"}
        ).status_code)
        self.assertEqual(409, self.client.post(
            execute_url, headers={"X-Execution-Token": self.execution_token}
        ).status_code)

        approve_url = self.gate_url + f"/actions/{action_id}/approve"
        self.assertEqual(401, self.client.post(approve_url, json={"note": "test"}).status_code)
        self.assertEqual(403, self.client.post(
            approve_url, json={"note": "test"}, headers={"X-Approval-Token": "wrong"}
        ).status_code)
        approval = self.client.post(
            approve_url, json={"note": "approved in disposable integration test"},
            headers={"X-Approval-Token": self.approver_token},
        )
        self.assertEqual(200, approval.status_code, approval.text)
        self.assertEqual("approved", approval.json()["status"])
        return action_id

    def signed_grant(self, *, target="api", expired=False):
        now = datetime.now(timezone.utc)
        issued = now - timedelta(seconds=60) if expired else now
        expires = now - timedelta(seconds=30) if expired else now + timedelta(seconds=30)
        return {
            "action_id": str(uuid.uuid4()),
            "proposal_sha256": "a" * 64,
            "action_type": "restart_service",
            "parameters": {"target": target},
            "decision": "ALLOW",
            "action_status": "validated",
            "approval_expires_at": None,
            "issued_at": issued.isoformat(),
            "expires_at": expires.isoformat(),
            "nonce": secrets.token_urlsafe(32),
        }

    def grant_signature(self, grant):
        canonical = json.dumps(grant, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        return hmac.new(self.executor_secret.encode(), canonical, hashlib.sha256).hexdigest()

    def test_full_approved_gate_executor_proxy_flow_and_security_controls(self):
        if self.mode != "success":
            self.skipTest("This pass is reserved for the successful disposable flow")
        action_id = self.new_approved_action()
        execute_url = self.gate_url + f"/actions/{action_id}/execute"
        self.assertEqual(401, self.client.post(execute_url).status_code)
        self.assertEqual(403, self.client.post(
            execute_url, headers={"X-Execution-Token": "wrong"}
        ).status_code)
        expired = self.signed_grant(expired=True)
        response = self.client.post(
            self.executor_url + "/execute", json=expired,
            headers={"X-Gate-Signature": self.grant_signature(expired)},
        )
        self.assertEqual(401, response.status_code, response.text)

        invalid_signature = self.signed_grant()
        response = self.client.post(
            self.executor_url + "/execute", json=invalid_signature,
            headers={"X-Gate-Signature": "0" * 64},
        )
        self.assertEqual(401, response.status_code, response.text)

        unauthorized_target = self.signed_grant(target="postgres")
        response = self.client.post(
            self.executor_url + "/execute", json=unauthorized_target,
            headers={"X-Gate-Signature": self.grant_signature(unauthorized_target)},
        )
        self.assertEqual(422, response.status_code, response.text)

        allowed_inspect = self.client.get(self.proxy_url + f"/containers/{self.target}/json")
        self.assertEqual(200, allowed_inspect.status_code, allowed_inspect.text)
        projected = allowed_inspect.json()
        self.assertIn("id", projected)
        self.assertNotIn("Config", projected)
        self.assertNotIn("Env", json.dumps(projected))
        self.assertEqual(403, self.client.get(
            self.proxy_url + "/containers/shopstack-api/json"
        ).status_code)
        self.assertEqual(403, self.client.post(
            self.proxy_url + f"/containers/{self.target}/stop"
        ).status_code)
        self.assertEqual(400, self.client.post(
            self.proxy_url + f"/containers/{self.target}/restart?t=1"
        ).status_code)

        response = self.client.post(
            execute_url, headers={"X-Execution-Token": self.execution_token}
        )
        self.assertEqual(200, response.status_code, response.text)
        result = response.json()
        self.assertEqual("executed", result["status"])
        self.assertTrue(result["executed"])
        self.assertNotIn("verified", result)
        replay = self.client.post(
            execute_url, headers={"X-Execution-Token": self.execution_token}
        )
        self.assertEqual(409, replay.status_code)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if self.client.get(self.api_url + "/").status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        else:
            self.fail("Disposable ShopStack API did not return after restart")

    def test_docker_failure_is_reported_without_retry(self):
        if self.mode != "docker_failure":
            self.skipTest("This pass runs after the disposable API target is stopped")
        inspect = self.client.get(self.proxy_url + f"/containers/{self.target}/json")
        self.assertEqual(404, inspect.status_code)
        restart = self.client.post(self.proxy_url + f"/containers/{self.target}/restart")
        self.assertEqual(404, restart.status_code)

        action_id = self.new_approved_action()
        execute_url = self.gate_url + f"/actions/{action_id}/execute"
        response = self.client.post(
            execute_url, headers={"X-Execution-Token": self.execution_token}
        )
        self.assertEqual(502, response.status_code, response.text)
        self.assertEqual("failed", response.json()["detail"]["result"]["status"])
        self.assertEqual(409, self.client.post(
            execute_url, headers={"X-Execution-Token": self.execution_token}
        ).status_code)


if __name__ == "__main__":
    unittest.main()
