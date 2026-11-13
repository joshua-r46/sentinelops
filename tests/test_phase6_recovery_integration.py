import concurrent.futures
import json
import os
import uuid
import unittest
from datetime import datetime, timedelta, timezone

import httpx
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

import recovery_policy
import snapshots

POLICY = os.environ["RECOVERY_POLICY_URL"]
SNAPSHOT = os.environ["SNAPSHOT_URL"]
DB = os.environ["DATABASE_URL"]
OPERATOR_TOKEN = os.environ["RECOVERY_OPERATOR_TOKEN"]
APPROVER_TOKEN = os.environ["RECOVERY_APPROVER_TOKEN"]
VERSION = "v1"


class DisposableRecoveryPolicyIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for _ in range(60):
            try:
                if httpx.get(POLICY + "/health", timeout=1).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            import time
            time.sleep(1)
        raise RuntimeError("Disposable recovery policy did not become healthy")

    def create_eligible_fixture(self, incident_id=None):
        incident_id, execution_id = incident_id or uuid.uuid4(), uuid.uuid4()
        with psycopg.connect(DB) as db:
            db.execute("INSERT INTO agentshield_incidents VALUES (%s,'GATED','open',NOW()) ON CONFLICT (id) DO UPDATE SET state='GATED',status='open',last_seen_at=NOW()", (incident_id,))
            db.execute("INSERT INTO agentshield_action_requests VALUES (%s,%s,'approved','REQUIRE_APPROVAL','restart_service',%s)",
                       (execution_id, incident_id, Jsonb({"target": "api"})))
        created = httpx.post(SNAPSHOT + "/snapshots", headers={"X-Snapshot-Token": os.environ["SNAPSHOT_TOKEN"]},
                             json={"incident_id": str(incident_id), "execution_id": str(execution_id), "target": "api"}, timeout=10)
        self.assertEqual(201, created.status_code, created.text)
        snapshot_id = uuid.UUID(created.json()["snapshot_id"])
        with psycopg.connect(DB) as db:
            db.execute("UPDATE agentshield_action_requests SET status='executed' WHERE id=%s", (execution_id,))
            db.execute("INSERT INTO agentshield_verifications VALUES (%s,%s,'api','FAILED','test_fixture',%s,%s,NOW(),NOW())",
                       (execution_id, incident_id, Jsonb({"fixture": True}), "b" * 64))
            db.execute("UPDATE agentshield_incidents SET state='ESCALATED' WHERE id=%s", (incident_id,))
        return incident_id, execution_id, snapshot_id

    def payload(self, fixture, action=True, request_id=None):
        incident_id, execution_id, snapshot_id = fixture
        body = {"request_id": str(request_id or uuid.uuid4()), "incident_id": str(incident_id),
                "execution_id": str(execution_id), "snapshot_id": str(snapshot_id)}
        if action:
            body["action"] = {"action_type": "rollback_deployment", "target": "api", "version": VERSION}
        return body

    def submit(self, body, token=OPERATOR_TOKEN):
        headers = {"X-Recovery-Token": token} if token else {}
        return httpx.post(POLICY + "/recovery/requests", headers=headers, json=body, timeout=10)

    def test_valid_request_requires_separate_approval_and_never_restores(self):
        fixture = self.create_eligible_fixture()
        response = self.submit(self.payload(fixture))
        self.assertEqual(201, response.status_code, response.text)
        recovery = response.json()
        self.assertEqual("pending_approval", recovery["status"])
        self.assertEqual(1, recovery["attempt_number"])
        self_approval = httpx.post(POLICY + f"/recovery/requests/{recovery['id']}/approve",
                                   headers={"X-Recovery-Approval-Token": OPERATOR_TOKEN},
                                   json={"note": "requester cannot approve"}, timeout=10)
        self.assertEqual(403, self_approval.status_code)
        approved = httpx.post(POLICY + f"/recovery/requests/{recovery['id']}/approve",
                              headers={"X-Recovery-Approval-Token": APPROVER_TOKEN},
                              json={"note": "authorized by separate operator"}, timeout=10)
        self.assertEqual(200, approved.status_code, approved.text)
        self.assertEqual("authorized", approved.json()["status"])
        replay_approval = httpx.post(POLICY + f"/recovery/requests/{recovery['id']}/approve",
                                     headers={"X-Recovery-Approval-Token": APPROVER_TOKEN},
                                     json={"note": "replay"}, timeout=10)
        self.assertEqual(409, replay_approval.status_code)
        self.assertEqual(404, httpx.post(POLICY + f"/recovery/requests/{recovery['id']}/execute").status_code)
        with psycopg.connect(DB) as db:
            state = db.execute("SELECT state FROM agentshield_incidents WHERE id=%s", (fixture[0],)).fetchone()[0]
        self.assertEqual("ESCALATED", state)

    def test_wrong_incident_and_execution_ids_are_rejected_and_audited(self):
        fixture = self.create_eligible_fixture()
        wrong_incident = self.payload(fixture)
        wrong_incident["incident_id"] = str(uuid.uuid4())
        self.assertEqual(409, self.submit(wrong_incident).status_code)
        wrong_execution = self.payload(fixture)
        wrong_execution["execution_id"] = str(uuid.uuid4())
        self.assertEqual(409, self.submit(wrong_execution).status_code)
        with psycopg.connect(DB) as db:
            rejected = db.execute("SELECT count(*) FROM agentshield_recovery_audit WHERE details->>'reason' IN ('incident_not_found','snapshot_incident_or_execution_mismatch')").fetchone()[0]
        self.assertGreaterEqual(rejected, 2)

    def test_missing_unsupported_and_unauthorized_requests_are_audited(self):
        fixture = self.create_eligible_fixture()
        missing_action = self.submit(self.payload(fixture, action=False))
        self.assertEqual(409, missing_action.status_code)
        unsupported = self.payload(fixture)
        unsupported["action"]["action_type"] = "shell"
        unsupported["action"]["target"] = "host"
        self.assertEqual(409, self.submit(unsupported).status_code)
        unauthorized = self.submit(self.payload(fixture), token=None)
        self.assertEqual(401, unauthorized.status_code)
        with psycopg.connect(DB) as db:
            events = db.execute("SELECT count(*) FROM agentshield_recovery_audit WHERE event_type IN ('recovery_request_rejected','recovery_authorization_rejected')").fetchone()[0]
        self.assertGreaterEqual(events, 3)

    def test_corrupt_snapshot_fails_independent_signature_check(self):
        fixture = self.create_eligible_fixture()
        with psycopg.connect(DB) as db:
            db.execute("ALTER TABLE agentshield_snapshots DISABLE TRIGGER agentshield_snapshots_immutable")
            row = db.execute("SELECT content FROM agentshield_snapshots WHERE id=%s", (fixture[2],)).fetchone()
            changed = {**row[0], "configuration": {**row[0]["configuration"], "version": "9.9.9"}}
            db.execute("UPDATE agentshield_snapshots SET content=%s,content_sha256=%s WHERE id=%s",
                       (Jsonb(changed), snapshots.digest(changed), fixture[2]))
            db.execute("ALTER TABLE agentshield_snapshots ENABLE TRIGGER agentshield_snapshots_immutable")
        response = self.submit(self.payload(fixture))
        self.assertEqual(409, response.status_code)
        self.assertIn("snapshot_external_signature_invalid", response.text)

    def test_legacy_sha_only_snapshot_is_not_recovery_eligible(self):
        fixture = self.create_eligible_fixture()
        with psycopg.connect(DB) as db:
            db.execute("ALTER TABLE agentshield_snapshots DISABLE TRIGGER agentshield_snapshots_immutable")
            db.execute("UPDATE agentshield_snapshots SET integrity_hmac_sha256=NULL WHERE id=%s", (fixture[2],))
            db.execute("ALTER TABLE agentshield_snapshots ENABLE TRIGGER agentshield_snapshots_immutable")
        response = self.submit(self.payload(fixture))
        self.assertEqual(409, response.status_code)
        self.assertIn("snapshot_external_signature_missing", response.text)

    def test_expired_snapshot_with_valid_signature_is_rejected(self):
        fixture = self.create_eligible_fixture()
        old_time = datetime.now(timezone.utc) - timedelta(days=2)
        with psycopg.connect(DB, row_factory=dict_row) as db:
            row = db.execute("SELECT * FROM agentshield_snapshots WHERE id=%s", (fixture[2],)).fetchone()
            key = snapshots.integrity_key()
            signature = snapshots.sign_snapshot(row["id"], row["incident_id"], row["execution_id"], row["target"],
                                                old_time, row["content"], row["content_sha256"], key)
            db.execute("ALTER TABLE agentshield_snapshots DISABLE TRIGGER agentshield_snapshots_immutable")
            db.execute("UPDATE agentshield_snapshots SET captured_at=%s,integrity_hmac_sha256=%s WHERE id=%s",
                       (old_time, signature, fixture[2]))
            db.execute("ALTER TABLE agentshield_snapshots ENABLE TRIGGER agentshield_snapshots_immutable")
        response = self.submit(self.payload(fixture))
        self.assertEqual(409, response.status_code)
        self.assertIn("snapshot_expired_or_from_future", response.text)

    def test_replay_and_concurrent_duplicate_requests_are_blocked(self):
        fixture = self.create_eligible_fixture()
        request_id = uuid.uuid4()
        body = self.payload(fixture, request_id=request_id)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: self.submit(body), range(2)))
        self.assertCountEqual([201, 409], [response.status_code for response in responses])
        self.assertEqual(409, self.submit(body).status_code)

    def test_recovery_attempt_limit_is_enforced(self):
        incident_id = uuid.uuid4()
        previous = []
        for _ in range(3):
            fixture = self.create_eligible_fixture(incident_id)
            response = self.submit(self.payload(fixture))
            self.assertEqual(201, response.status_code, response.text)
            previous.append(response.json()["id"])
            with psycopg.connect(DB) as db:
                db.execute("UPDATE agentshield_recovery_requests SET status='failed' WHERE id=%s", (response.json()["id"],))
        next_fixture = self.create_eligible_fixture(incident_id)
        limited = self.submit(self.payload(next_fixture))
        self.assertEqual(409, limited.status_code)
        self.assertIn("recovery_attempt_limit_reached", limited.text)

    def test_z_recovery_audit_chain_detects_tampering(self):
        fixture = self.create_eligible_fixture()
        self.assertEqual(201, self.submit(self.payload(fixture)).status_code)
        headers = {"X-Recovery-Token": OPERATOR_TOKEN}
        self.assertTrue(httpx.get(POLICY + "/audit/verify", headers=headers, timeout=5).json()["valid"])
        with psycopg.connect(DB) as db:
            db.execute("ALTER TABLE agentshield_recovery_audit DISABLE TRIGGER agentshield_recovery_audit_immutable")
            db.execute("UPDATE agentshield_recovery_audit SET details=details || '{\"tampered\":true}'::jsonb WHERE sequence_id=(SELECT max(sequence_id) FROM agentshield_recovery_audit)")
            db.execute("ALTER TABLE agentshield_recovery_audit ENABLE TRIGGER agentshield_recovery_audit_immutable")
        audit = httpx.get(POLICY + "/audit/verify", headers=headers, timeout=5)
        self.assertEqual(200, audit.status_code)
        self.assertFalse(audit.json()["valid"])
        self.assertIsNotNone(audit.json()["first_invalid_sequence"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
