import os
import time
import uuid
import unittest

import httpx
import psycopg

SNAPSHOT_URL = os.environ["SNAPSHOT_URL"]
TOKEN = os.environ["SNAPSHOT_TOKEN"]
DB = os.environ["DATABASE_URL"]
API = os.environ["API_URL"]
DEPLOYER = os.environ["DEPLOYER_URL"]


class DisposableSnapshotIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with psycopg.connect(DB) as db:
            db.execute("CREATE TABLE IF NOT EXISTS agentshield_incidents (id UUID PRIMARY KEY, state TEXT NOT NULL, status TEXT NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS agentshield_action_requests (id UUID PRIMARY KEY, incident_id UUID NOT NULL, status TEXT NOT NULL, decision TEXT NOT NULL, action_type TEXT NOT NULL, parameters JSONB NOT NULL)")
        for _ in range(60):
            try:
                if (httpx.get(SNAPSHOT_URL + "/health", timeout=1).status_code == 200 and
                    httpx.get(API + "/health", timeout=1).json().get("status") == "healthy" and
                    httpx.get(DEPLOYER + "/health", timeout=1).json().get("status") == "healthy"):
                    return
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError("Disposable snapshot services did not become healthy")

    def test_capture_authentication_immutable_integrity_and_audit(self):
        incident_id, execution_id = uuid.uuid4(), uuid.uuid4()
        with psycopg.connect(DB) as db:
            db.execute("INSERT INTO agentshield_incidents VALUES (%s,'APPROVAL_PENDING','open',NOW())", (incident_id,))
            db.execute("INSERT INTO agentshield_action_requests VALUES (%s,%s,'approved','REQUIRE_APPROVAL','restart_service',%s)",
                       (execution_id, incident_id, psycopg.types.json.Jsonb({"target": "api"})))
        deployment = httpx.post(DEPLOYER + "/deployments", json={
            "service_name": "api", "version": "phase6-test-version", "previous_version": "1.0.0",
            "change_type": "integration-test", "description": "disposable fixture",
        }, timeout=10)
        self.assertEqual(201, deployment.status_code, deployment.text)

        payload = {"incident_id": str(incident_id), "execution_id": str(execution_id), "target": "api"}
        unauthorized = httpx.post(SNAPSHOT_URL + "/snapshots", json=payload, timeout=5)
        self.assertEqual(401, unauthorized.status_code)
        headers = {"X-Snapshot-Token": TOKEN}
        created = httpx.post(SNAPSHOT_URL + "/snapshots", headers=headers, json=payload, timeout=10)
        self.assertEqual(201, created.status_code, created.text)
        metadata = created.json()
        self.assertEqual(str(incident_id), metadata["incident_id"])
        self.assertEqual(str(execution_id), metadata["execution_id"])
        self.assertTrue(metadata["captured_at"])
        snapshot_id = metadata["snapshot_id"]

        unauthorized_read = httpx.get(SNAPSHOT_URL + "/snapshots/" + snapshot_id, timeout=5)
        self.assertEqual(401, unauthorized_read.status_code)
        retrieved = httpx.get(SNAPSHOT_URL + "/snapshots/" + snapshot_id, headers=headers, timeout=5)
        self.assertEqual(200, retrieved.status_code, retrieved.text)
        snapshot = retrieved.json()
        self.assertEqual("verified", snapshot["integrity"])
        self.assertEqual(str(incident_id), snapshot["incident_id"])
        self.assertEqual(str(execution_id), snapshot["execution_id"])
        entry = snapshot["content"]["deployment_state"]["entries"][0]
        self.assertEqual("phase6-test-version", entry["version"])
        self.assertNotIn("description", entry)

        no_mutation_route = httpx.put(SNAPSHOT_URL + "/snapshots/" + snapshot_id, headers=headers, json={"content": {}}, timeout=5)
        self.assertEqual(405, no_mutation_route.status_code)
        with self.assertRaises(psycopg.errors.RaiseException):
            with psycopg.connect(DB) as db:
                db.execute("UPDATE agentshield_snapshots SET content=content || '{\"tampered\":true}'::jsonb WHERE id=%s", (snapshot_id,))

        with psycopg.connect(DB) as db:
            db.execute("ALTER TABLE agentshield_snapshots DISABLE TRIGGER agentshield_snapshots_immutable")
            db.execute("UPDATE agentshield_snapshots SET content=content || '{\"tampered\":true}'::jsonb WHERE id=%s", (snapshot_id,))
            db.execute("ALTER TABLE agentshield_snapshots ENABLE TRIGGER agentshield_snapshots_immutable")
        corrupted = httpx.get(SNAPSHOT_URL + "/snapshots/" + snapshot_id, headers=headers, timeout=5)
        self.assertEqual(409, corrupted.status_code)
        with psycopg.connect(DB) as db:
            audit = db.execute("SELECT count(*) FROM agentshield_action_audit WHERE action_request_id=%s AND event_type='snapshot_integrity_failed'", (execution_id,)).fetchone()[0]
        self.assertEqual(1, audit)


if __name__ == "__main__":
    unittest.main()
