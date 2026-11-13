import asyncio
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

AGENT_DIR = str(Path(__file__).resolve().parents[1] / "agentshield")
sys.path.insert(0, AGENT_DIR)
import llm_gateway
import telegram


def diagnosis_payload(evidence_id: str):
    return {
        "cause": "API dependency response degraded",
        "confidence": 0.82,
        "uncertainty": "Redis or upstream latency needs operator review.",
        "recommended_action": "read_metrics",
        "recommended_target": "api",
        "recommended_parameters": {},
        "evidence_ids": [evidence_id],
    }


class LlmGatewayTests(unittest.TestCase):
    def test_disabled_fails_closed_and_auth_is_required(self):
        with patch.dict(os.environ, {"LLM_ENABLED": "false", "GEMINI_API_KEY": "",
                                     "GEMINI_MODEL": "", "LLM_GATEWAY_TOKEN": ""}):
            importlib.reload(llm_gateway)
            with TestClient(llm_gateway.app) as client:
                self.assertEqual(client.post("/diagnose", json={"summary": "x", "evidence": []}).status_code, 503)

    def test_redaction_covers_credentials_endpoints_ips_and_infrastructure_fields(self):
        safe = llm_gateway.redact({
            "password": "do-not-send",
            "log": "token=never-send request to https://internal.example/x at 10.3.4.5",
            "host": "private-node.example",
            "service": "api",
        })
        self.assertEqual(safe["password"], "[REDACTED]")
        self.assertEqual(safe["host"], "[REDACTED]")
        self.assertNotIn("never-send", safe["log"])
        self.assertNotIn("internal.example", safe["log"])
        self.assertNotIn("10.3.4.5", safe["log"])
        self.assertEqual("api", safe["service"])

    def test_typed_contract_rejects_unknown_action_and_unknown_evidence(self):
        evidence_id = str(uuid.uuid4())
        invalid = diagnosis_payload(evidence_id)
        invalid["recommended_action"] = "docker_exec"
        with self.assertRaises(ValidationError):
            llm_gateway.Diagnosis.model_validate(invalid)
        unauthorized = diagnosis_payload(evidence_id) | {"authorized": True, "approved": True}
        with self.assertRaises(ValidationError):
            llm_gateway.Diagnosis.model_validate(unauthorized)
        with self.assertRaises(ValueError):
            llm_gateway.validate_diagnosis(diagnosis_payload(str(uuid.uuid4())), {evidence_id})

    def test_google_genai_sdk_is_called_with_pydantic_json_schema(self):
        evidence_id = str(uuid.uuid4())
        observed = {}

        class FakeTypes:
            @staticmethod
            def HttpOptions(**kwargs):
                return kwargs

            @staticmethod
            def GenerateContentConfig(**kwargs):
                return types.SimpleNamespace(**kwargs)

        class FakeModels:
            def generate_content(self, **kwargs):
                observed.update(kwargs)
                return types.SimpleNamespace(text=json.dumps(diagnosis_payload(evidence_id)))

        class FakeClient:
            def __init__(self, **kwargs):
                observed["client_config"] = kwargs
                self.models = FakeModels()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                observed["closed"] = True

        fake_genai = types.ModuleType("google.genai")
        fake_genai.Client = FakeClient
        fake_genai.types = FakeTypes
        fake_google = types.ModuleType("google")
        fake_google.__path__ = []
        fake_google.genai = fake_genai
        with (patch.dict(sys.modules, {"google": fake_google, "google.genai": fake_genai}),
              patch.object(llm_gateway, "GEMINI_API_KEY", "test-key-not-logged"),
              patch.object(llm_gateway, "GEMINI_MODEL", "gemini-test")):
            result = llm_gateway._generate_gemini({"summary": "synthetic", "evidence": []})
        self.assertEqual("application/json", observed["config"].response_mime_type)
        self.assertIs(llm_gateway.Diagnosis, observed["config"].response_schema)
        self.assertEqual("gemini-test", observed["model"])
        self.assertTrue(observed["closed"])
        self.assertEqual(evidence_id, result["evidence_ids"][0])

    def test_cloud_payload_is_redacted_and_diagnosis_keeps_typed_metadata(self):
        evidence_id = str(uuid.uuid4())
        captured = {}

        def generated(payload):
            captured.update(payload)
            return diagnosis_payload(evidence_id)

        request = llm_gateway.DiagnosisRequest(
            summary="redis endpoint token=must-not-leave-local",
            evidence=[{"id": evidence_id, "content": {"host": "10.0.0.15", "password": "private"}}],
        )
        with (patch.object(llm_gateway, "ENABLED", True),
              patch.object(llm_gateway, "PROVIDER", "gemini"),
              patch.object(llm_gateway, "GEMINI_API_KEY", "test-key"),
              patch.object(llm_gateway, "GEMINI_MODEL", "gemini-test"),
              patch.object(llm_gateway, "SERVICE_TOKEN", "s" * 40),
              patch.object(llm_gateway, "_generate_gemini", side_effect=generated)):
            result = asyncio.run(llm_gateway.diagnose(request, authorization="Bearer " + "s" * 40))
        self.assertEqual("[REDACTED]", captured["evidence"][0]["content"]["host"])
        self.assertNotIn("must-not-leave-local", json.dumps(captured))
        self.assertEqual(evidence_id, result.evidence_ids[0])
        self.assertEqual(0.82, result.confidence)
        self.assertIn("operator review", result.uncertainty)
        self.assertEqual("read_metrics", result.recommended_action)
        self.assertEqual("api", result.recommended_target)
        self.assertEqual("gemini", result.provider)

    def test_provider_failure_returns_generic_error_without_echoing_provider_details(self):
        evidence_id = str(uuid.uuid4())
        with (patch.object(llm_gateway, "ENABLED", True),
              patch.object(llm_gateway, "PROVIDER", "gemini"),
              patch.object(llm_gateway, "GEMINI_API_KEY", "synthetic-test-key"),
              patch.object(llm_gateway, "GEMINI_MODEL", "gemini-test"),
              patch.object(llm_gateway, "SERVICE_TOKEN", "s" * 40),
              patch.object(llm_gateway, "_generate_gemini",
                           side_effect=RuntimeError("provider failure api_key=synthetic-do-not-echo"))):
            with self.assertLogs(llm_gateway.LOGGER, level="WARNING") as records:
                with TestClient(llm_gateway.app) as client:
                    response = client.post(
                        "/diagnose",
                        json={"summary": "synthetic dependency timeout", "evidence": [{"id": evidence_id}]},
                        headers={"Authorization": "Bearer " + "s" * 40},
                    )
        self.assertEqual(502, response.status_code)
        self.assertEqual({"detail": "LLM provider response was unavailable or invalid"}, response.json())
        self.assertNotIn("synthetic-do-not-echo", response.text)
        self.assertIn("outcome=failure", records.output[0])
        self.assertIn("elapsed_ms=", records.output[0])
        self.assertNotIn("synthetic-do-not-echo", records.output[0])

    def test_provider_success_records_timing_without_sensitive_payload(self):
        evidence_id = str(uuid.uuid4())
        with (patch.object(llm_gateway, "ENABLED", True),
              patch.object(llm_gateway, "PROVIDER", "gemini"),
              patch.object(llm_gateway, "GEMINI_API_KEY", "synthetic-key-not-to-log"),
              patch.object(llm_gateway, "GEMINI_MODEL", "gemini-test"),
              patch.object(llm_gateway, "SERVICE_TOKEN", "s" * 40),
              patch.object(llm_gateway, "_generate_gemini", return_value=diagnosis_payload(evidence_id))):
            with self.assertLogs(llm_gateway.LOGGER, level="INFO") as records:
                with TestClient(llm_gateway.app) as client:
                    response = client.post(
                        "/diagnose",
                        json={"summary": "synthetic incident", "evidence": [{"id": evidence_id}]},
                        headers={"Authorization": "Bearer " + "s" * 40},
                    )
        self.assertEqual(200, response.status_code)
        self.assertIn("outcome=success", records.output[0])
        self.assertIn("elapsed_ms=", records.output[0])
        self.assertNotIn("synthetic-key-not-to-log", records.output[0])


class DiagnosisEngineIntegrationTests(unittest.TestCase):
    def test_cloud_diagnosis_route_requires_operator_authorization(self):
        import importlib.util
        from fastapi import HTTPException

        engine_spec = importlib.util.spec_from_file_location("agentshield_diagnosis_auth", Path(AGENT_DIR) / "main.py")
        engine = importlib.util.module_from_spec(engine_spec)
        engine_spec.loader.exec_module(engine)
        with (patch.dict(os.environ, {"LLM_ENABLED": "true"}),
              patch.object(engine, "LLM_GATEWAY_TOKEN", "g" * 40),
              patch.object(engine, "LLM_DIAGNOSIS_TOKEN", "d" * 40),
              patch.object(engine, "conn") as database):
            with self.assertRaises(HTTPException) as caught:
                engine.llm(uuid.uuid4(), x_llm_diagnosis_token=None)
        self.assertEqual(401, caught.exception.status_code)
        database.assert_not_called()

    def test_structured_gateway_diagnosis_is_persisted_without_authorizing_action(self):
        import importlib.util
        import psycopg.types.json

        engine_spec = importlib.util.spec_from_file_location("agentshield_diagnosis_engine", Path(AGENT_DIR) / "main.py")
        engine = importlib.util.module_from_spec(engine_spec)
        engine_spec.loader.exec_module(engine)
        incident_id, evidence_id = uuid.uuid4(), uuid.uuid4()
        response_payload = diagnosis_payload(str(evidence_id)) | {"provider": "gemini", "model": "gemini-test"}
        calls = []

        class Cursor:
            def __init__(self, row=None, rows=None):
                self.row = row
                self.rows = rows or []

            def fetchone(self):
                return self.row

            def fetchall(self):
                return self.rows

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def execute(self, query, params=()):
                calls.append((query, params))
                if "FROM agentshield_incidents" in query:
                    return Cursor(row={"id": incident_id, "summary": "synthetic API degradation"})
                if "FROM agentshield_evidence" in query:
                    return Cursor(rows=[{"id": evidence_id, "redacted_content": {"service": "api"}}])
                if "INSERT INTO agentshield_diagnoses" in query:
                    return Cursor(row={"incident_id": incident_id, "conclusion": params[3],
                                       "confidence": params[4], "evidence": params[5],
                                       "evidence_ids": params[6], "action_type": params[7],
                                       "model_used": params[8]})
                raise AssertionError("unexpected database query")

        class GatewayResponse:
            status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return response_payload

        class GatewayClient:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def post(self, url, *, json, headers):
                calls.append(("gateway", {"url": url, "payload": json, "headers": headers}))
                return GatewayResponse()

        with (patch.dict(os.environ, {"LLM_ENABLED": "true"}),
              patch.object(engine, "LLM_GATEWAY_TOKEN", "g" * 40),
              patch.object(engine, "LLM_DIAGNOSIS_TOKEN", "d" * 40),
              patch.object(engine, "conn", return_value=Connection()),
              patch.object(engine.httpx, "Client", return_value=GatewayClient())):
            result = engine.llm(incident_id, x_llm_diagnosis_token="d" * 40)

        self.assertEqual("synthetic API degradation", calls[2][1]["payload"]["summary"])
        stored = result["evidence"].obj
        self.assertEqual("Redis or upstream latency needs operator review.", stored["uncertainty"])
        self.assertEqual("read_metrics", result["action_type"])
        self.assertEqual([str(evidence_id)], result["evidence_ids"].obj)
        self.assertEqual("gemini:gemini-test", result["model_used"])
        self.assertFalse(any("/actions" in str(item) or "/execute" in str(item) for item in calls))


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self.is_success = 200 <= status_code < 300
        self._payload = payload or {}

    def json(self):
        return self._payload


def telegram_update(update_id, user_id, text, *, chat_type="private", chat_id=None):
    return {"update_id": update_id, "message": {
        "from": {"id": int(user_id)},
        "chat": {"id": int(chat_id if chat_id is not None else user_id), "type": chat_type},
        "text": text,
    }}


class TelegramOperatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="agentshield-telegram-test-")
        self.db_path = str(Path(self.temp.name) / "telegram-state.sqlite3")
        self.patches = [
            patch.object(telegram, "STATE_DB", self.db_path),
            patch.object(telegram, "BOT_TOKEN", "fake-bot-token"),
            patch.object(telegram, "ALLOWED_USER_IDS", {"2468"}),
            patch.object(telegram, "NOTIFY_IDS", {"2468"}),
            patch.object(telegram, "SERVICE_TOKEN", "service-token-" + "x" * 32),
            patch.object(telegram, "APPROVER_TOKEN", "approver-token-" + "y" * 32),
            patch.object(telegram, "QUEUE_TOKEN", "service-token-" + "x" * 32),
        ]
        for item in self.patches:
            item.start()
        telegram.init_state()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    async def test_allowlisted_approval_and_denial_use_safety_gate_only(self):
        approve_id, deny_id = str(uuid.uuid4()), str(uuid.uuid4())
        response = FakeResponse(200, {"id": approve_id, "status": "approved"})
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request", new=AsyncMock(return_value=response)) as request):
            self.assertEqual("completed", await telegram.dispatch_update(telegram_update(1, "2468", f"/approve {approve_id}")))
            self.assertEqual("completed", await telegram.dispatch_update(telegram_update(2, "2468", f"/deny {deny_id}")))
        self.assertEqual(2, request.await_count)
        self.assertTrue(request.await_args_list[0].args[1].endswith(f"/actions/{approve_id}/approve"))
        self.assertTrue(request.await_args_list[1].args[1].endswith(f"/actions/{deny_id}/reject"))
        self.assertEqual("approver-token-" + "y" * 32, request.await_args_list[0].kwargs["headers"]["X-Approval-Token"])
        self.assertIn("Telegram approve by allowlisted user 2468", request.await_args_list[0].kwargs["json_body"]["note"])
        self.assertEqual(2, send.await_count)

    async def test_update_replay_is_rejected_durably_and_decision_is_not_repeated(self):
        action_id = str(uuid.uuid4())
        with (patch.object(telegram, "send", new=AsyncMock()),
              patch.object(telegram, "internal_request", new=AsyncMock(return_value=FakeResponse(200, {}))) as request):
            update = telegram_update(44, "2468", f"/approve {action_id}")
            self.assertEqual("completed", await telegram.dispatch_update(update))
            self.assertEqual("duplicate_update", await telegram.dispatch_update(update))
        self.assertEqual(1, request.await_count)
        self.assertEqual(45, telegram.read_offset())
        with telegram.state_connection() as db:
            events = [row[0] for row in db.execute("SELECT event FROM telegram_audit ORDER BY id").fetchall()]
        self.assertIn("approval_approve", events)
        self.assertIn("duplicate_update_rejected", events)

    async def test_expired_or_duplicate_gate_decision_is_rejected_and_audited(self):
        action_id = str(uuid.uuid4())
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request", new=AsyncMock(return_value=FakeResponse(409, {"detail": "expired"})))):
            result = await telegram.dispatch_update(telegram_update(45, "2468", f"/approve {action_id}"))
        self.assertEqual("completed", result)
        self.assertIn("expired or already decided", send.await_args.args[1])
        with telegram.state_connection() as db:
            event = db.execute("SELECT event FROM telegram_audit WHERE update_id=45 ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertEqual("approval_duplicate_or_expired_rejected", event)

    async def test_unauthorized_users_and_group_commands_cannot_decide(self):
        with (patch.object(telegram, "send", new=AsyncMock()),
              patch.object(telegram, "internal_request", new=AsyncMock()) as request):
            unauthorized = await telegram.dispatch_update(telegram_update(50, "9999", "/status"))
            group = await telegram.dispatch_update(telegram_update(51, "2468", f"/approve {uuid.uuid4()}", chat_type="group", chat_id=-100))
        self.assertEqual("unauthorized", unauthorized)
        self.assertEqual("unauthorized", group)
        request.assert_not_awaited()

    async def test_status_and_approval_queue_commands_are_read_only(self):
        responses = [FakeResponse(200, {"service": "agentshield", "status": "healthy", "mode": "read_only"}),
                     FakeResponse(200, {"items": []})]
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request", new=AsyncMock(side_effect=responses)) as request):
            self.assertEqual("completed", await telegram.dispatch_update(telegram_update(60, "2468", "/status")))
            self.assertEqual("completed", await telegram.dispatch_update(telegram_update(61, "2468", "/approvals")))
        self.assertEqual("GET", request.await_args_list[0].args[0])
        self.assertTrue(request.await_args_list[1].args[1].endswith("/approvals/pending"))
        self.assertEqual("service-token-" + "x" * 32,
                         request.await_args_list[1].kwargs["headers"]["X-Telegram-Queue-Token"])
        self.assertIn("No pending approvals", send.await_args_list[1].args[1])

    async def test_start_and_help_are_allowlisted_read_only_commands(self):
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request", new=AsyncMock()) as request):
            self.assertEqual("completed", await telegram.dispatch_update(telegram_update(63, "2468", "/start")))
            self.assertEqual("completed", await telegram.dispatch_update(telegram_update(64, "2468", "/help")))
        request.assert_not_awaited()
        self.assertEqual(2, send.await_count)
        self.assertIn("/incidents", send.await_args_list[0].args[1])
        self.assertIn("cannot run infrastructure commands", send.await_args_list[1].args[1])

    async def test_incidents_command_lists_bounded_redacted_read_only_records(self):
        records = [{"id": str(uuid.uuid4()), "state": "DETECTED", "status": "open",
                    "summary": "Synthetic incident host=10.3.4.5 token=do-not-send"}]
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request",
                           new=AsyncMock(return_value=FakeResponse(200, records))) as request):
            result = await telegram.dispatch_update(telegram_update(65, "2468", "/incidents"))
        self.assertEqual("completed", result)
        request.assert_awaited_once_with("GET", telegram.INCIDENTS_URL)
        self.assertIn("Synthetic incident", send.await_args.args[1])
        self.assertIn("[REDACTED_IP]", send.await_args.args[1])
        self.assertNotIn("10.3.4.5", send.await_args.args[1])
        self.assertNotIn("do-not-send", send.await_args.args[1])

    async def test_incident_command_shows_redacted_incident_status(self):
        incident_id = str(uuid.uuid4())
        response = FakeResponse(200, {"id": incident_id, "state": "ESCALATED", "status": "open",
                                      "summary": "api host=10.1.2.3 degraded"})
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request", new=AsyncMock(return_value=response)) as request):
            result = await telegram.dispatch_update(telegram_update(62, "2468", f"/incident {incident_id}"))
        self.assertEqual("completed", result)
        self.assertTrue(request.await_args.args[1].endswith("/incidents/" + incident_id))
        self.assertIn("ESCALATED", send.await_args.args[1])
        self.assertNotIn("10.1.2.3", send.await_args.args[1])

    async def test_incident_notification_uses_internal_auth_and_sends_allowlisted_recipients(self):
        with patch.object(telegram, "send", new=AsyncMock()) as send:
            result = await telegram.notify(
                telegram.Notice(text="Synthetic incident created"),
                authorization="Bearer " + "service-token-" + "x" * 32,
            )
        self.assertEqual({"sent": 1, "failed": 0}, result)
        send.assert_awaited_once_with("2468", "Synthetic incident created")

    async def test_unsupported_infrastructure_command_never_calls_services(self):
        with (patch.object(telegram, "send", new=AsyncMock()) as send,
              patch.object(telegram, "internal_request", new=AsyncMock()) as request):
            result = await telegram.dispatch_update(telegram_update(70, "2468", "/docker rm shopstack"))
        self.assertEqual("completed", result)
        request.assert_not_awaited()
        self.assertIn("Unsupported command", send.await_args.args[1])

    async def test_polling_uses_mock_telegram_updates_and_persistent_offset(self):
        update = telegram_update(80, "2468", "/help")
        with (patch.object(telegram, "telegram_api", new=AsyncMock(return_value=[update])) as bot_api,
              patch.object(telegram, "send", new=AsyncMock()) as send):
            count = await telegram.poll_once()
        self.assertEqual(1, count)
        self.assertEqual("getUpdates", bot_api.await_args.args[0])
        self.assertEqual(0, bot_api.await_args.kwargs["params"]["offset"])
        self.assertEqual(81, telegram.read_offset())
        send.assert_awaited_once()


class SafetyGateQueueTests(unittest.TestCase):
    def test_pending_queue_requires_internal_token_and_returns_bounded_rows(self):
        import importlib.util
        from fastapi import HTTPException

        gate_spec = importlib.util.spec_from_file_location(
            "agentshield_phase3_queue", Path(__file__).resolve().parents[1] / "phase3policy" / "main.py")
        gate = importlib.util.module_from_spec(gate_spec)
        gate_spec.loader.exec_module(gate)
        items = [{"id": str(uuid.uuid4()), "action_type": "restart_service", "target": "api"}]
        observed = {}

        class Cursor:
            def fetchall(self):
                return items

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def execute(self, query, params=()):
                observed["query"] = query
                observed["params"] = params
                return Cursor()

        token = "q" * 40
        with (patch.object(gate, "TELEGRAM_QUEUE_TOKEN", token),
              patch.object(gate, "conn", return_value=Connection())):
            self.assertEqual(items, gate.pending_approvals(token)["items"])
            with self.assertRaises(HTTPException) as missing:
                gate.pending_approvals(None)
            self.assertEqual(401, missing.exception.status_code)
            with self.assertRaises(HTTPException) as invalid:
                gate.pending_approvals("wrong")
            self.assertEqual(403, invalid.exception.status_code)
        self.assertIn("status='pending_approval'", observed["query"])
        self.assertIn("LIMIT 100", observed["query"])


class TelegramHealthTests(unittest.TestCase):
    def test_health_does_not_expose_bot_token(self):
        result = telegram.health()
        self.assertNotIn("token", result)

    def test_notification_requires_internal_authorization(self):
        with tempfile.TemporaryDirectory(prefix="agentshield-telegram-http-test-") as temp:
            with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "TELEGRAM_ALLOWED_CHAT_IDS": "",
                                         "TELEGRAM_ALLOWED_USER_IDS": "", "TELEGRAM_SERVICE_TOKEN": "",
                                         "TELEGRAM_STATE_DB": str(Path(temp) / "state.sqlite3")}):
                importlib.reload(telegram)
                with TestClient(telegram.app) as client:
                    self.assertEqual(client.post("/notify", json={"text": "test"}).status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
