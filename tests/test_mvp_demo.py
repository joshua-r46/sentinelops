import os
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agentshield"))
os.environ["AGENTSHIELD_DEMO_MODE"] = "test"
import mvp_demo


class DemoWorkflowTests(unittest.TestCase):
    def test_two_approved_runs_require_approval_and_are_simulated(self):
        with TestClient(mvp_demo.app) as client:
            for _ in range(2):
                started = client.post("/demo/run", json={}).json()
                self.assertEqual(started["status"], "approval_pending")
                view = client.get("/demo/overview").json()
                diagnosis = next(e for e in view["events"] if e["kind"] == "diagnosis")
                evidence = next(e for e in view["events"] if e["kind"] == "simulated_test_evidence")
                self.assertIn(__import__("json").loads(evidence["payload"])["evidence_id"], diagnosis["payload"])
                self.assertEqual(client.post(f"/demo/actions/{started['action_id']}/approve", json={"approved": True}).status_code, 200)
                self.assertEqual(client.post(f"/demo/actions/{started['action_id']}/approve", json={"approved": True}).status_code, 409)
            view = client.get("/demo/overview").json()
            self.assertEqual(len(view["incidents"]), 2)
            self.assertTrue(all(i["state"] == "RESOLVED_SIMULATED" for i in view["incidents"]))
            self.assertTrue(all(e["kind"] != "real_infrastructure_failure" for e in view["events"]))

    def test_denial_escalates_and_execution_is_never_real(self):
        with TestClient(mvp_demo.app) as client:
            started = client.post("/demo/run", json={}).json()
            result = client.post(f"/demo/actions/{started['action_id']}/approve", json={"approved": False}).json()
            self.assertEqual(result["incident_state"], "ESCALATED")
            self.assertEqual(result["simulated"], True)
            self.assertFalse(any("executed\":true" in e["payload"] for e in client.get("/demo/overview").json()["events"]))


if __name__ == "__main__":
    unittest.main()
