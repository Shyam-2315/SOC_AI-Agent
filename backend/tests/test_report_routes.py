import unittest
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import FastAPI
import httpx

from app.api.dependencies import get_current_user
from app.api.routes.reports import router
from app.core.exceptions import register_exception_handlers
from app.core.middleware import RequestContextMiddleware
from app.services import ai_copilot_service
from app.services import incidents as incidents_service
from app.services import threat_intel_service
from tests.test_detection_rules import FakeCollection


class ReportRouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "incident_alerts": incidents_service.alerts_collection,
            "incident_incidents": incidents_service.incidents_collection,
            "incident_correlated": incidents_service.correlated_incidents_collection,
            "incident_actions": incidents_service.response_actions_collection,
            "ti_alerts": threat_intel_service.alerts_collection,
            "ti_incidents": threat_intel_service.incidents_collection,
            "ai_alerts": ai_copilot_service.alerts_collection,
            "ai_incidents": ai_copilot_service.incidents_collection,
            "ai_actions": ai_copilot_service.response_actions_collection,
            "ai_blocks": ai_copilot_service.security_blocks_collection,
        }
        self.incident_id = ObjectId()
        self.other_tenant_incident_id = ObjectId()
        self.alert_id = ObjectId()
        self.alerts = FakeCollection(
            [
                {
                    "_id": self.alert_id,
                    "organization_id": "org-1",
                    "event_type": "windows_failed_login",
                    "severity": "high",
                    "message": "Repeated failed login from 203.0.113.10",
                    "ip_address": "203.0.113.10",
                    "source_ip": "203.0.113.10",
                    "hostname": "web-01",
                    "mitre_tactic_id": "TA0006",
                    "mitre_tactic_name": "Credential Access",
                    "mitre_technique_id": "T1110",
                    "mitre_technique_name": "Brute Force",
                    "timestamp": datetime(2026, 6, 1, tzinfo=timezone.utc),
                }
            ]
        )
        self.incidents = FakeCollection(
            [
                {
                    "_id": self.incident_id,
                    "organization_id": "org-1",
                    "title": "Brute force against web tier",
                    "description": "Credential attack from known malicious IP",
                    "severity": "high",
                    "status": "new",
                    "related_alert_ids": [str(self.alert_id)],
                    "investigation_notes": "Analyst confirmed repeated authentication failures.",
                    "timestamp": datetime(2026, 6, 1, tzinfo=timezone.utc),
                },
                {
                    "_id": self.other_tenant_incident_id,
                    "organization_id": "org-2",
                    "title": "Other tenant incident",
                    "description": "Should not be visible to org-1",
                    "severity": "critical",
                    "status": "new",
                    "timestamp": datetime(2026, 6, 1, tzinfo=timezone.utc),
                },
            ]
        )
        self.actions = FakeCollection(
            [
                {
                    "_id": ObjectId(),
                    "organization_id": "org-1",
                    "alert_id": str(self.alert_id),
                    "action_type": "block_ip",
                    "automated_actions": ["Blocked malicious IP: 203.0.113.10"],
                    "ip_address": "203.0.113.10",
                    "timestamp": datetime(2026, 6, 1, 0, 5, tzinfo=timezone.utc),
                }
            ]
        )
        self.empty = FakeCollection()

        incidents_service.alerts_collection = self.alerts
        incidents_service.incidents_collection = self.incidents
        incidents_service.correlated_incidents_collection = self.empty
        incidents_service.response_actions_collection = self.actions
        threat_intel_service.alerts_collection = self.alerts
        threat_intel_service.incidents_collection = self.incidents
        ai_copilot_service.alerts_collection = self.alerts
        ai_copilot_service.incidents_collection = self.incidents
        ai_copilot_service.response_actions_collection = self.actions
        ai_copilot_service.security_blocks_collection = self.empty

        self.app = FastAPI()
        self.app.add_middleware(RequestContextMiddleware)
        register_exception_handlers(self.app)
        self.app.include_router(router)

        async def current_user():
            return {
                "user_id": "user-1",
                "email": "analyst@example.com",
                "role": "analyst",
                "organization_id": "org-1",
                "disabled": False,
            }

        self.app.dependency_overrides[get_current_user] = current_user

    async def asyncTearDown(self):
        incidents_service.alerts_collection = self.originals["incident_alerts"]
        incidents_service.incidents_collection = self.originals["incident_incidents"]
        incidents_service.correlated_incidents_collection = self.originals["incident_correlated"]
        incidents_service.response_actions_collection = self.originals["incident_actions"]
        threat_intel_service.alerts_collection = self.originals["ti_alerts"]
        threat_intel_service.incidents_collection = self.originals["ti_incidents"]
        ai_copilot_service.alerts_collection = self.originals["ai_alerts"]
        ai_copilot_service.incidents_collection = self.originals["ai_incidents"]
        ai_copilot_service.response_actions_collection = self.originals["ai_actions"]
        ai_copilot_service.security_blocks_collection = self.originals["ai_blocks"]
        self.app.dependency_overrides.clear()

    async def _client(self):
        transport = httpx.ASGITransport(app=self.app)
        return httpx.AsyncClient(transport=transport, base_url="http://test")

    async def test_authenticated_technical_report_endpoint(self):
        async with await self._client() as client:
            response = await client.get(
                f"/api/reports/incidents/{self.incident_id}",
                params={"report_type": "technical"},
            )

        self.assertEqual(response.status_code, 200)
        report = response.json()["report"]
        self.assertEqual(report["report_type"], "technical")
        self.assertEqual(report["incident_id"], str(self.incident_id))
        self.assertTrue(report["recommended_actions"])

    async def test_executive_report_endpoint(self):
        async with await self._client() as client:
            response = await client.get(f"/api/reports/incidents/{self.incident_id}/executive")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["report"]["report_type"], "executive")

    async def test_compliance_report_endpoint(self):
        async with await self._client() as client:
            response = await client.get(f"/api/reports/incidents/{self.incident_id}/compliance")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["report"]["report_type"], "compliance")

    async def test_json_endpoint_returns_raw_structured_report(self):
        async with await self._client() as client:
            response = await client.get(f"/api/reports/incidents/{self.incident_id}/json")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["report_type"], "technical")
        self.assertEqual(payload["incident_id"], str(self.incident_id))
        self.assertIn("generated_at", payload)

    async def test_missing_incident_returns_404(self):
        async with await self._client() as client:
            response = await client.get(f"/api/reports/incidents/{ObjectId()}/technical")

        self.assertEqual(response.status_code, 404)

    async def test_cross_tenant_incident_access_blocked(self):
        async with await self._client() as client:
            response = await client.get(
                f"/api/reports/incidents/{self.other_tenant_incident_id}/technical"
            )

        self.assertEqual(response.status_code, 404)

    async def test_unauthenticated_request_rejected(self):
        self.app.dependency_overrides.clear()
        async with await self._client() as client:
            response = await client.get(f"/api/reports/incidents/{self.incident_id}/technical")

        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
