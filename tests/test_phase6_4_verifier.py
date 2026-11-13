import asyncio
import importlib.util
import pathlib
import sys
import unittest
import uuid
from unittest import mock

import httpx
import psycopg
from fastapi import HTTPException

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agentshield"))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_module("agentshield_verifier_phase64", ROOT / "agentshield" / "verifier.py")
import recovery_policy


INCIDENT = uuid.uuid4()
RECOVERY_ID = uuid.uuid4()
DIGEST = "sha256:" + "a" * 64


def request_model(incident_id=INCIDENT, recovery_id=RECOVERY_ID):
    return verifier.RecoveryVerificationRequest(
        incident_id=incident_id,
        recovery_request_id=recovery_id,
        target="api",
        expected_version="v1",
        expected_image_digest=DIGEST,
        expected_config_revision="config-r1",
        expected_resource_limits={"memory_bytes": 512, "nano_cpus": 1000},
    )


class RecoveryProbeTests(unittest.IsolatedAsyncioTestCase):
    async def probe(self, case="success"):
        request = request_model()

        async def respond(req):
            if case == "inconclusive" and req.url.path == "/health":
                raise httpx.ConnectError("unavailable", request=req)
            if req.url.path == "/__deployment":
                identity = {
                    "service": "api",
                    "version": "v2" if case == "identity_mismatch" else request.expected_version,
                    "image_digest": request.expected_image_digest,
                    "config_revision": request.expected_config_revision,
                    "resource_limits": request.expected_resource_limits,
                }
                return httpx.Response(200, json=identity, request=req)
            if req.url.path == "/health":
                status = 503 if case == "health_failed" else 200
                return httpx.Response(status, json={"status": "unhealthy" if status == 503 else "healthy"}, request=req)
            if req.url.path == "/":
                return httpx.Response(200, json={"application": "ShopStack", "service": "api"}, request=req)
            if req.url.path == "/metrics":
                return httpx.Response(200, json={"requests_total": 10, "error_rate": 0.0,
                                                 "average_latency_ms": 1.0}, request=req)
            if req.method == "POST" and req.url.path == "/orders":
                status = 500 if case == "journey_failed" else 422
                return httpx.Response(status, json={"detail": "invalid input"}, request=req)
            if req.method == "GET" and req.url.path.startswith("/orders/"):
                return httpx.Response(404, json={"detail": "Order not found"}, request=req)
            return httpx.Response(404, request=req)

        client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
        try:
            with mock.patch.object(verifier, "API_URL", "http://shopstack.test"):
                return await verifier.probe_recovery(client, request)
        finally:
            await client.aclose()

    async def test_success_checks_identity_health_readiness_and_read_only_journeys(self):
        result = await self.probe()
        self.assertEqual("PASSED", result["outcome"])
        self.assertTrue(all(check["passed"] for check in result["checks"].values()))
        self.assertIn("order_lookup_journey", result["checks"])
        self.assertIn("order_input_validation", result["checks"])

    async def test_failed_health_probe_fails_recovery(self):
        result = await self.probe("health_failed")
        self.assertEqual("FAILED", result["outcome"])
        self.assertIn("service_health", result["failure_reasons"])

    async def test_failed_user_journey_fails_recovery(self):
        result = await self.probe("journey_failed")
        self.assertEqual("FAILED", result["outcome"])
        self.assertIn("order_input_validation", result["failure_reasons"])

    async def test_deployment_identity_mismatch_fails_recovery(self):
        result = await self.probe("identity_mismatch")
        self.assertEqual("FAILED", result["outcome"])
        self.assertIn("deployment_identity", result["failure_reasons"])

    async def test_transport_uncertainty_is_inconclusive(self):
        result = await self.probe("inconclusive")
        self.assertEqual("INCONCLUSIVE", result["outcome"])
        self.assertIn("service_health", result["inconclusive_reasons"])


class FakeVerifierDatabase:
    def __init__(self, state="ESCALATED"):
        self.state = state
        self.recovery_ids = set()
        self.sql = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, query, params=()):
        self.sql.append((query, params))
        if "INSERT INTO agentshield_verifications VALUES" in query:
            recovery_id = params[0]
            if recovery_id in self.recovery_ids:
                raise psycopg.errors.UniqueViolation("duplicate recovery verification")
            self.recovery_ids.add(recovery_id)
        if "SET state='VERIFYING'" in query:
            self.state = "VERIFYING"
        elif "UPDATE agentshield_incidents SET state=%s" in query:
            self.state = params[0]
        return self

    def fetchone(self):
        if self.state in {"ESCALATED", "VERIFYING", "EXECUTING", "RESOLVED"}:
            return {"id": INCIDENT, "state": self.state}
        return None


class RecoveryStateTransitionTests(unittest.IsolatedAsyncioTestCase):
    async def run_verification(self, outcome, db=None, recovery_id=RECOVERY_ID):
        db = db or FakeVerifierDatabase()
        sample = {"outcome": outcome,
                  "checks": {"service_health": {"passed": outcome == "PASSED"}},
                  "failure_reasons": [] if outcome == "PASSED" else ["service_health"],
                  "inconclusive_reasons": ["service_health"] if outcome == "INCONCLUSIVE" else []}
        with (mock.patch.object(verifier, "conn", return_value=db),
              mock.patch.object(verifier, "PROBE_COUNT", 1),
              mock.patch.object(verifier, "PROBE_INTERVAL", 0),
              mock.patch.object(verifier, "probe_recovery", new=mock.AsyncMock(return_value=sample))):
            result = await verifier.verify_recovery(request_model(recovery_id=recovery_id))
        return db, result

    async def test_only_successful_verification_resolves_incident_and_records_evidence(self):
        db, result = await self.run_verification("PASSED")
        self.assertEqual("RESOLVED", db.state)
        self.assertEqual("PASSED", result["outcome"])
        sql = " ".join(query for query, _ in db.sql)
        self.assertIn("INSERT INTO agentshield_evidence", sql)
        self.assertIn("recovery_verification_passed", [params[2] for query, params in db.sql
                                                         if "INSERT INTO agentshield_action_audit" in query])

    async def test_failed_verification_returns_incident_to_escalated(self):
        db, result = await self.run_verification("FAILED")
        self.assertEqual("ESCALATED", db.state)
        self.assertEqual("FAILED", result["outcome"])

    async def test_inconclusive_verification_never_resolves_incident(self):
        db, result = await self.run_verification("INCONCLUSIVE")
        self.assertEqual("ESCALATED", db.state)
        self.assertEqual("INCONCLUSIVE", result["outcome"])

    async def test_incident_cannot_resolve_before_verification_claim(self):
        db = FakeVerifierDatabase(state="EXECUTING")
        with mock.patch.object(verifier, "conn", return_value=db):
            with self.assertRaises(HTTPException) as caught:
                await verifier.verify_recovery(request_model())
        self.assertEqual(409, caught.exception.status_code)
        self.assertEqual("EXECUTING", db.state)

    async def test_duplicate_and_concurrent_verification_requests_are_rejected(self):
        db = FakeVerifierDatabase()
        await self.run_verification("FAILED", db=db)
        with mock.patch.object(verifier, "conn", return_value=db):
            with self.assertRaises(HTTPException) as duplicate:
                await verifier.verify_recovery(request_model())
        self.assertEqual(409, duplicate.exception.status_code)

        in_progress = FakeVerifierDatabase()
        entered_probe, release_probe = asyncio.Event(), asyncio.Event()
        passing_sample = {"outcome": "PASSED", "checks": {}, "failure_reasons": [],
                          "inconclusive_reasons": []}

        async def held_probe(*_):
            entered_probe.set()
            await release_probe.wait()
            return passing_sample

        with (mock.patch.object(verifier, "conn", return_value=in_progress),
              mock.patch.object(verifier, "PROBE_COUNT", 1),
              mock.patch.object(verifier, "PROBE_INTERVAL", 0),
              mock.patch.object(verifier, "probe_recovery", new=held_probe)):
            first = asyncio.create_task(verifier.verify_recovery(request_model(recovery_id=uuid.uuid4())))
            await entered_probe.wait()
            with self.assertRaises(HTTPException) as concurrent:
                await verifier.verify_recovery(request_model(recovery_id=uuid.uuid4()))
            self.assertEqual(409, concurrent.exception.status_code)
            self.assertEqual("VERIFYING", in_progress.state)
            release_probe.set()
            passed = await first
        self.assertEqual("PASSED", passed["outcome"])
        self.assertEqual("RESOLVED", in_progress.state)


class RecoveryPolicyVerificationGateTests(unittest.TestCase):
    def test_executor_success_does_not_override_failed_independent_verification(self):
        incident_id, request_id, snapshot_id, execution_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

        class PolicyConnection:
            def __init__(self):
                self.updates = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def execute(self, query, params=()):
                self.updates.append((query, params))

        db = PolicyConnection()
        recovery_row = {"incident_id": incident_id, "source_execution_id": execution_id,
                        "snapshot_id": snapshot_id, "version": "v1"}
        snapshot = {"content": {"deployment": {"image_digest": DIGEST,
                    "config_revision": "config-r1", "resource_limits": {"memory_bytes": 512, "nano_cpus": 1000}}}}
        verifier_result = {"incident_id": str(incident_id), "verification_id": str(request_id),
                           "outcome": "FAILED", "incident_state": "ESCALATED",
                           "reason": "service_health", "evidence_id": str(uuid.uuid4()),
                           "evidence_sha256": "b" * 64, "samples": 3}

        class Response:
            status_code = 200

            def json(self):
                return verifier_result

        with (mock.patch.object(recovery_policy, "conn", return_value=db),
              mock.patch.object(recovery_policy, "append_audit") as audit,
              mock.patch.object(recovery_policy.httpx, "post", return_value=Response()) as post):
            result = recovery_policy.verify_restored_deployment(
                request_id, "operator", recovery_row, snapshot, {"executed": True})

        self.assertEqual("verification_failed", result["status"])
        self.assertFalse(result["incident_resolved"])
        self.assertEqual("verify-recovery", post.call_args.args[0].rsplit("/", 1)[-1])
        self.assertTrue(audit.call_args.args[3]["executor_reported_success"])
        self.assertEqual("verification_failed", db.updates[0][1][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
