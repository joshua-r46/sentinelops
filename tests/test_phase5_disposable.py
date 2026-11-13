import os
import time
import uuid
import unittest

import httpx
import psycopg

VERIFIER = os.environ["VERIFIER_URL"]
TOKEN = os.environ["VERIFIER_TOKEN"]
DB = os.environ["DATABASE_URL"]
API = os.environ["API_URL"]
WORKER = os.environ["WORKER_URL"]


class DisposableVerifierIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with psycopg.connect(DB) as db:
            db.execute("CREATE TABLE IF NOT EXISTS agentshield_incidents (id UUID PRIMARY KEY, state TEXT NOT NULL, status TEXT NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS agentshield_evidence (id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id), source TEXT NOT NULL, kind TEXT NOT NULL, redacted_content JSONB NOT NULL, content_sha256 TEXT NOT NULL, duplicate_of UUID, collected_at TIMESTAMPTZ NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS agentshield_incident_transitions (id UUID PRIMARY KEY, incident_id UUID REFERENCES agentshield_incidents(id), from_state TEXT, to_state TEXT NOT NULL, reason TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS agentshield_action_audit (id UUID PRIMARY KEY, action_request_id UUID, event_type TEXT NOT NULL, actor TEXT NOT NULL, details JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL)")
        for _ in range(60):
            try:
                verifier_ok = httpx.get(VERIFIER + "/health", timeout=1).status_code == 200
                api_ok = httpx.get(API + "/health", timeout=1).json().get("status") == "healthy"
                worker_ok = httpx.get(WORKER + "/health", timeout=1).json().get("status") == "healthy"
                if verifier_ok and api_ok and worker_ok:
                    return
            except (httpx.HTTPError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError("Disposable verifier did not become healthy")

    def test_real_api_worker_baseline_verification_and_audit(self):
        incident_id, execution_id = uuid.uuid4(), uuid.uuid4()
        with psycopg.connect(DB) as db:
            db.execute("INSERT INTO agentshield_incidents VALUES (%s,'GATED','open',NOW())", (incident_id,))
        headers = {"X-Verifier-Token": TOKEN}
        rejected = httpx.post(VERIFIER + "/baselines", json={"incident_id": str(incident_id), "target": "api"}, timeout=5)
        self.assertEqual(401, rejected.status_code)
        baseline = httpx.post(VERIFIER + "/baselines", headers=headers,
                              json={"incident_id": str(incident_id), "target": "api"}, timeout=10)
        self.assertEqual(201, baseline.status_code, baseline.text)
        with psycopg.connect(DB) as db:
            db.execute("UPDATE agentshield_incidents SET state='EXECUTING' WHERE id=%s", (incident_id,))
        verified = httpx.post(VERIFIER + "/verify", headers=headers,
                              json={"incident_id": str(incident_id), "execution_id": str(execution_id), "target": "api"}, timeout=15)
        self.assertEqual(200, verified.status_code, verified.text)
        body = verified.json()
        self.assertEqual("PASSED", body["outcome"])
        self.assertEqual("RESOLVED", body["incident_state"])
        self.assertEqual(3, body["probes"])
        with psycopg.connect(DB) as db:
            incident = db.execute("SELECT state FROM agentshield_incidents WHERE id=%s", (incident_id,)).fetchone()
            history = db.execute("SELECT outcome,incident_id FROM agentshield_verifications WHERE execution_id=%s", (execution_id,)).fetchone()
            evidence = db.execute("SELECT count(*) FROM agentshield_evidence WHERE incident_id=%s", (incident_id,)).fetchone()[0]
            events = db.execute("SELECT count(*) FROM agentshield_action_audit WHERE action_request_id=%s AND event_type='verification_passed'", (execution_id,)).fetchone()[0]
        self.assertEqual("RESOLVED", incident[0])
        self.assertEqual(("PASSED", incident_id), history)
        self.assertEqual(1, evidence)
        self.assertEqual(1, events)

    def test_failed_live_verification_persists_failure_and_escalates(self):
        incident_id, execution_id = uuid.uuid4(), uuid.uuid4()
        with psycopg.connect(DB) as db:
            db.execute("INSERT INTO agentshield_incidents VALUES (%s,'GATED','open',NOW())", (incident_id,))
        headers = {"X-Verifier-Token": TOKEN}
        baseline = httpx.post(VERIFIER + "/baselines", headers=headers,
                              json={"incident_id": str(incident_id), "target": "api"}, timeout=10)
        self.assertEqual(201, baseline.status_code, baseline.text)
        for _ in range(8):
            response = httpx.get(API + "/test-error", timeout=5)
            self.assertEqual(500, response.status_code)
        with psycopg.connect(DB) as db:
            db.execute("UPDATE agentshield_incidents SET state='EXECUTING' WHERE id=%s", (incident_id,))
        verified = httpx.post(VERIFIER + "/verify", headers=headers,
                              json={"incident_id": str(incident_id), "execution_id": str(execution_id), "target": "api"}, timeout=15)
        self.assertEqual(200, verified.status_code, verified.text)
        body = verified.json()
        self.assertEqual("FAILED", body["outcome"])
        self.assertEqual("ESCALATED", body["incident_state"])
        with psycopg.connect(DB) as db:
            incident = db.execute("SELECT state FROM agentshield_incidents WHERE id=%s", (incident_id,)).fetchone()
            history = db.execute("SELECT outcome,incident_id FROM agentshield_verifications WHERE execution_id=%s", (execution_id,)).fetchone()
            event = db.execute("SELECT count(*) FROM agentshield_action_audit WHERE action_request_id=%s AND event_type='verification_failed'", (execution_id,)).fetchone()[0]
        self.assertEqual("ESCALATED", incident[0])
        self.assertEqual(("FAILED", incident_id), history)
        self.assertEqual(1, event)


if __name__ == "__main__":
    unittest.main()
