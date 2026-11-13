import asyncio
import unittest
from unittest.mock import patch

import dashboard


class FakeResponse:
    status_code = 200

    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


class FakeClient:
    async def get(self, url):
        if url.endswith("/incidents"):
            return FakeResponse([{"id": "i-1", "summary": "API unavailable", "evidence": {"secret": "never expose"}}])
        if url.endswith("/deployments"):
            return FakeResponse([{"deployment_id": "d-1", "version": "v2", "status": "verified", "database_url": "hidden"}])
        if url.endswith("/health"):
            return FakeResponse({"status": "healthy", "secret": "hidden"})
        if url.endswith("/metrics"):
            return FakeResponse({"status": "healthy", "jobs_total": 7})
        return FakeResponse({})


class DashboardAdapterTests(unittest.TestCase):
    def test_projection_removes_unapproved_fields(self):
        self.assertEqual(dashboard._rows(
            {"available": True, "http_status": 200,
             "data": [{"id": "i-1", "summary": "safe", "evidence": {"secret": "hidden"}}]},
            ("id", "summary")),
            {"available": True, "http_status": 200, "data": [{"id": "i-1", "summary": "safe"}]})

    def test_unavailable_shape_is_explicit(self):
        self.assertEqual(dashboard._object({"available": False, "data": None}, ("status",)),
                         {"available": False, "data": None})

    def test_overview_uses_live_api_contracts_and_projects_safe_data(self):
        async def gather_side_effect(*coroutines):
            values = await asyncio.gather(*coroutines)
            return values

        with patch.object(dashboard.httpx, "AsyncClient") as client_type:
            client_type.return_value.__aenter__.return_value = FakeClient()
            result = asyncio.run(dashboard.overview())
        self.assertEqual(result["incidents"]["data"][0]["id"], "i-1")
        self.assertNotIn("evidence", result["incidents"]["data"][0])
        self.assertEqual(result["deployments"]["data"][0]["version"], "v2")
        self.assertNotIn("database_url", result["deployments"]["data"][0])
        self.assertFalse(result["capabilities"]["phase_6_4_verification"])


if __name__ == "__main__":
    unittest.main()
