import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

os.environ["EXECUTOR_SHARED_SECRET"] = "phase4-test-secret-with-at-least-32-bytes"
os.environ["EXECUTOR_STATE_DB"] = "/tmp/agentshield-phase4-import-test.sqlite3"
ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("phase4_executor", ROOT / "executor" / "main.py")
executor_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor_module)


class FakeDocker:
    def __init__(self, *, running=True, health=None, change_id=False, fail_restart=False):
        self.running = running
        self.health = health
        self.change_id = change_id
        self.fail_restart = fail_restart
        self.restarts = 0
        self.inspects = 0

    def inspect_api(self):
        self.inspects += 1
        return {
            "id": "container-api-2" if self.change_id and self.restarts else "container-api-1",
            "image": "sha256:immutable-image",
            "config": {"labels": {"org.opencontainers.image.version": "1.2.3", "secret": "must-not-leak"}, "env": ["PASSWORD=do-not-return"]},
            "host_config": {"restart_policy": {"name": "unless-stopped"}, "binds": ["/sensitive:/host"]},
            "state": {"running": self.running, "status": "running" if self.running else "exited", "health": self.health},
        }

    def restart_api(self):
        self.restarts += 1
        if self.fail_restart:
            raise RuntimeError("synthetic proxy failure")


class ExecutorFoundationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.docker = FakeDocker()
        self.executor = executor_module.Executor(self.docker, str(pathlib.Path(self.tmp.name) / "ledger.sqlite3"))
        self.grant = self.make_grant()

    def tearDown(self):
        self.tmp.cleanup()

    def make_grant(self, **overrides):
        current = datetime.now(timezone.utc)
        values = {
            "action_id": uuid.uuid4(),
            "proposal_sha256": hashlib.sha256(b"proposal").hexdigest(),
            "action_type": "restart_service",
            "parameters": {"target": "api"},
            "decision": "ALLOW",
            "action_status": "validated",
            "approval_expires_at": None,
            "issued_at": current.isoformat(),
            "expires_at": (current + timedelta(seconds=30)).isoformat(),
            "nonce": "nonce-" + uuid.uuid4().hex + uuid.uuid4().hex,
        }
        values.update(overrides)
        return executor_module.Grant(**values)

    @staticmethod
    def sign(grant):
        body = executor_module.canonical(grant.model_dump(mode="json"))
        return hmac.new(executor_module.SECRET.encode(), body, hashlib.sha256).hexdigest()

    def test_signed_restart_records_allowlisted_pre_action_snapshot(self):
        result = self.executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual(("executed", True, "api"), (result["status"], result["executed"], result["target"]))
        self.assertEqual(1, self.docker.restarts)
        self.assertEqual(1, self.docker.inspects)
        self.assertEqual("container-api-1", result["snapshot"]["container_id"])
        serialized = json.dumps(result)
        self.assertNotIn("must-not-leak", serialized)
        self.assertNotIn("do-not-return", serialized)
        self.assertNotIn("/sensitive", serialized)

    def test_invalid_signature_expires_and_unsupported_actions_fail_closed(self):
        with self.assertRaises(executor_module.HTTPException) as invalid:
            self.executor.execute(self.grant, "0" * 64)
        self.assertEqual(401, invalid.exception.status_code)
        expired = self.make_grant(expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
        with self.assertRaises(executor_module.HTTPException) as stale:
            self.executor.execute(expired, self.sign(expired))
        self.assertEqual(401, stale.exception.status_code)
        unsupported = self.make_grant(action_type="drop_database")
        with self.assertRaises(executor_module.HTTPException) as blocked:
            self.executor.execute(unsupported, self.sign(unsupported))
        self.assertEqual(422, blocked.exception.status_code)
        self.assertEqual(0, self.docker.restarts)

    def test_approval_is_bound_to_current_status_and_expiry(self):
        not_approved = self.make_grant(decision="REQUIRE_APPROVAL", action_status="pending_approval",
                                       approval_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())
        with self.assertRaises(executor_module.HTTPException) as pending:
            self.executor.execute(not_approved, self.sign(not_approved))
        self.assertEqual(403, pending.exception.status_code)
        expired_approval = self.make_grant(decision="REQUIRE_APPROVAL", action_status="approved",
                                           approval_expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
        with self.assertRaises(executor_module.HTTPException) as stale:
            self.executor.execute(expired_approval, self.sign(expired_approval))
        self.assertEqual(403, stale.exception.status_code)
        current_approval = self.make_grant(decision="REQUIRE_APPROVAL", action_status="approved",
                                           approval_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat())
        self.assertTrue(self.executor.execute(current_approval, self.sign(current_approval))["executed"])

    def test_replay_and_concurrent_duplicate_cannot_restart_twice(self):
        outcomes = []
        barrier = threading.Barrier(2)
        def run():
            barrier.wait()
            try:
                outcomes.append(self.executor.execute(self.grant, self.sign(self.grant))["status"])
            except executor_module.HTTPException as exc:
                outcomes.append(exc.status_code)
        first = threading.Thread(target=run)
        second = threading.Thread(target=run)
        first.start(); second.start(); first.join(); second.join()
        self.assertCountEqual(["executed", 409], outcomes)
        self.assertEqual(1, self.docker.restarts)

    def test_http_route_requires_signed_grant_and_executes_only_typed_contract(self):
        original_enabled, original_executor = executor_module.ENABLED, executor_module.executor
        executor_module.ENABLED, executor_module.executor = True, self.executor
        try:
            with TestClient(executor_module.app) as client:
                missing = client.post("/execute", json=self.grant.model_dump(mode="json"))
                self.assertEqual(401, missing.status_code, missing.text)
                headers = {"X-Gate-Signature": self.sign(self.grant)}
                accepted = client.post("/execute", json=self.grant.model_dump(mode="json"), headers=headers)
                self.assertEqual(200, accepted.status_code, accepted.text)
                self.assertEqual("executed", accepted.json()["status"])
                replay = client.post("/execute", json=self.grant.model_dump(mode="json"), headers=headers)
                self.assertEqual(409, replay.status_code)
                self.assertEqual(1, self.docker.restarts)
        finally:
            executor_module.ENABLED, executor_module.executor = original_enabled, original_executor

    def test_docker_restart_failure_is_recorded_and_not_replayed(self):
        self.docker.fail_restart = True
        with self.assertRaises(executor_module.HTTPException) as failure:
            self.executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual(502, failure.exception.status_code)
        self.assertEqual("failed", failure.exception.detail["status"])
        import sqlite3
        with sqlite3.connect(self.executor.db_path) as db:
            status = db.execute("SELECT status FROM executions WHERE action_id=?", (str(self.grant.action_id),)).fetchone()[0]
        self.assertEqual("failed", status)
        with self.assertRaises(executor_module.HTTPException) as replay:
            self.executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual(409, replay.exception.status_code)
        self.assertEqual(1, self.docker.restarts)

    def test_nonrunning_target_fails_before_restart(self):
        self.docker.running = False
        with self.assertRaises(executor_module.HTTPException) as failure:
            self.executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual(502, failure.exception.status_code)
        self.assertEqual("failed", failure.exception.detail["status"])
        self.assertEqual(0, self.docker.restarts)


class DockerSocketFilterTests(unittest.TestCase):
    def test_inspection_projection_excludes_secrets_and_host_configuration(self):
        path = ROOT / "executor" / "socket_proxy.py"
        spec = importlib.util.spec_from_file_location("phase4_socket_proxy", path)
        proxy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(proxy)
        projected = proxy.project_inspect({
            "Id": "container-id", "Image": "sha256:image",
            "Config": {"Labels": {"org.opencontainers.image.version": "1.2", "secret": "hidden"}, "Env": ["TOKEN=x"]},
            "HostConfig": {"RestartPolicy": {"Name": "unless-stopped"}, "Binds": ["/host:/host"]},
            "State": {"Running": True, "Status": "running", "Health": {"Status": "healthy"}},
        })
        encoded = json.dumps(projected)
        self.assertEqual("container-id", projected["id"])
        self.assertEqual("healthy", projected["state"]["health"])
        self.assertNotIn("hidden", encoded)
        self.assertNotIn("TOKEN", encoded)
        self.assertNotIn("/host", encoded)
        self.assertIsNotNone(proxy.ROUTE.fullmatch("/v1.43/containers/shopstack-api/restart"))
        self.assertIsNone(proxy.ROUTE.fullmatch("/containers/shopstack-worker/restart"))
        self.assertIsNone(proxy.ROUTE.fullmatch("/containers/shopstack-api/exec"))


if __name__ == "__main__":
    unittest.main()
