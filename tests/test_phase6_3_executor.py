import copy
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMP = tempfile.TemporaryDirectory(prefix="agentshield-phase6-3-")
KEY_PATH = pathlib.Path(TEMP.name) / "snapshot.key"
KEY = b"phase6-3-snapshot-integrity-key-0001"
KEY_PATH.write_bytes(KEY)
os.environ["EXECUTOR_SHARED_SECRET"] = "phase6-3-executor-shared-secret-0001"
os.environ["EXECUTOR_STATE_DB"] = str(pathlib.Path(TEMP.name) / "global.sqlite3")
os.environ["SNAPSHOT_INTEGRITY_KEY_FILE"] = str(KEY_PATH)
os.environ["DEPLOYMENT_CATALOG_FILE"] = str(ROOT / "deployment" / "catalog.json")
SPEC = importlib.util.spec_from_file_location("phase6_3_executor", ROOT / "executor" / "main.py")
executor_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(executor_module)


class FakeProxy:
    def __init__(self):
        self.versions = []

    def restore_deployment(self, version):
        self.versions.append(version)
        return {"status": "candidate_active", "version": version, "incumbent_retained": True,
                "phase6_4_required": True, "image_digest": "sha256:fixture"}


class UncertainProxy(FakeProxy):
    def restore_deployment(self, version):
        self.versions.append(version)
        raise executor_module.DeploymentProxyError("cutover_failed", "uncertain")


class Phase63ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.proxy = FakeProxy()
        self.executor = executor_module.Executor(self.proxy, str(pathlib.Path(self.temp.name) / "ledger.sqlite3"))
        self.envelope = self.make_envelope()
        self.grant = self.make_grant()

    def tearDown(self):
        self.temp.cleanup()

    def make_envelope(self):
        catalog = json.loads((ROOT / "deployment" / "catalog.json").read_text())
        entry = catalog["versions"]["v1"]
        content = {"deployment": {"version": "v1", "image_digest": entry["image_digest"],
                                   "config_revision": entry["profile"]["config_revision"],
                                   "resource_limits": entry["profile"]["resources"]}}
        content_sha = hashlib.sha256(executor_module.canonical(content)).hexdigest()
        captured = datetime.now(timezone.utc).isoformat()
        base = {"snapshot_id": str(uuid.uuid4()), "incident_id": str(uuid.uuid4()),
                "execution_id": str(uuid.uuid4()), "target": "api", "captured_at": captured,
                "content": content, "content_sha256": content_sha}
        message = executor_module.canonical(base)
        base["integrity_hmac_sha256"] = hmac.new(KEY, message, hashlib.sha256).hexdigest()
        return base

    def make_grant(self, envelope=None, parameters=None):
        now = datetime.now(timezone.utc)
        return executor_module.Grant(
            action_id=uuid.uuid4(), proposal_sha256=hashlib.sha256(b"proposal").hexdigest(),
            action_type="rollback_deployment", parameters=parameters or {"service": "api", "version": "v1"},
            decision="REQUIRE_APPROVAL", action_status="approved",
            approval_expires_at=(now + timedelta(minutes=1)).isoformat(), issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=30)).isoformat(), nonce=uuid.uuid4().hex * 2,
            snapshot_envelope=envelope or self.envelope)

    @staticmethod
    def sign(grant):
        body = executor_module.canonical(grant.model_dump(mode="json"))
        return hmac.new(executor_module.SECRET.encode(), body, hashlib.sha256).hexdigest()

    def test_typed_rollback_validates_signed_catalog_snapshot_and_consumes_grant_once(self):
        result = self.executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual("executed", result["status"])
        self.assertTrue(result["phase6_4_required"])
        self.assertEqual(["v1"], self.proxy.versions)
        with self.assertRaises(executor_module.HTTPException) as replay:
            self.executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual(409, replay.exception.status_code)
        self.assertEqual(["v1"], self.proxy.versions)

    def test_snapshot_hmac_version_and_extra_docker_parameters_fail_before_proxy(self):
        tampered = copy.deepcopy(self.envelope)
        tampered["content"]["deployment"]["config_revision"] = "changed"
        grant = self.make_grant(envelope=tampered)
        with self.assertRaises(executor_module.HTTPException) as invalid_hmac:
            self.executor.execute(grant, self.sign(grant))
        self.assertEqual(403, invalid_hmac.exception.status_code)
        wrong_version = self.make_grant(parameters={"service": "api", "version": "v2"})
        with self.assertRaises(executor_module.HTTPException) as mismatch:
            self.executor.execute(wrong_version, self.sign(wrong_version))
        self.assertEqual(403, mismatch.exception.status_code)
        arbitrary = self.make_grant(parameters={"service": "api", "version": "v1", "image": "hostile"})
        with self.assertRaises(executor_module.HTTPException) as rejected:
            self.executor.execute(arbitrary, self.sign(arbitrary))
        self.assertEqual(422, rejected.exception.status_code)
        self.assertEqual([], self.proxy.versions)

    def test_failed_cutover_records_uncertain_compensation_and_is_not_retried(self):
        proxy = UncertainProxy()
        executor = executor_module.Executor(proxy, str(pathlib.Path(self.temp.name) / "failure-ledger.sqlite3"))
        with self.assertRaises(executor_module.HTTPException) as failure:
            executor.execute(self.grant, self.sign(self.grant))
        self.assertEqual(502, failure.exception.status_code)
        self.assertEqual("uncertain", failure.exception.detail["compensation"])
        self.assertEqual(["v1"], proxy.versions)


if __name__ == "__main__":
    unittest.main()
