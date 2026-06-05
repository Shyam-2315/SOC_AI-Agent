import unittest
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import FastAPI
import httpx

from app.api.dependencies import get_current_user
from app.api.routes.copilot_v2 import router
from app.repositories import attack_chain_repository
from app.services import copilot_v2_service, incidents as incident_service
from tests.test_attack_chains import QueryFakeCollection


def _alert(
    alert_id: ObjectId,
    *,
    organization_id: str = "org-1",
    message: str = "Repeated failed login from 203.0.113.10",
    severity: str = "high",
) -> dict:
    return {
        "_id": alert_id,
        "organization_id": organization_id,
        "title": "Credential access alert",
        "event_type": "windows_failed_login",
        "severity": severity,
        "message": message,
        "ip_address": "203.0.113.10",
        "source_ip": "203.0.113.10",
        "hostname": "web-01",
        "username": "admin",
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
    }


class CopilotV2RouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "copilot_alerts": copilot_v2_service.alerts_collection,
            "copilot_actions": copilot_v2_service.response_actions_collection,
            "incident_alerts": incident_service.alerts_collection,
            "incident_incidents": incident_service.incidents_collection,
            "incident_actions": incident_service.response_actions_collection,
            "incident_correlated": incident_service.correlated_incidents_collection,
            "chains": attack_chain_repository.attack_chains_collection,
        }
        self.alert_id = ObjectId()
        self.incident_id = ObjectId()
        self.other_incident_id = ObjectId()
        self.chain_id = ObjectId()
        self.alerts = QueryFakeCollection([_alert(self.alert_id)])
        self.incidents = QueryFakeCollection(
            [
                {
                    "_id": self.incident_id,
                    "organization_id": "org-1",
                    "title": "Brute force against web tier",
                    "description": "Credential attack against admin account.",
                    "severity": "critical",
                    "status": "new",
                    "related_alert_ids": [str(self.alert_id)],
                    "timestamp": datetime.now(timezone.utc),
                },
                {
                    "_id": self.other_incident_id,
                    "organization_id": "org-2",
                    "title": "Other tenant incident",
                    "description": "Should not be visible.",
                    "severity": "critical",
                    "status": "new",
                    "timestamp": datetime.now(timezone.utc),
                },
            ]
        )
        self.actions = QueryFakeCollection(
            [
                {
                    "_id": ObjectId(),
                    "organization_id": "org-1",
                    "incident_id": str(self.incident_id),
                    "alert_id": str(self.alert_id),
                    "action_type": "block_ip",
                    "automated_actions": ["Blocked malicious IP: 203.0.113.10"],
                    "timestamp": datetime.now(timezone.utc),
                }
            ]
        )
        self.chains = QueryFakeCollection(
            [
                {
                    "_id": self.chain_id,
                    "organization_id": "org-1",
                    "title": "Threat story: Credential Access on web-01",
                    "status": "open",
                    "severity": "critical",
                    "risk_score": 9.1,
                    "confidence_score": 0.86,
                    "related_alert_ids": [str(self.alert_id)],
                    "related_incident_ids": [str(self.incident_id)],
                    "affected_hosts": ["web-01"],
                    "affected_users": ["admin"],
                    "source_ips": ["203.0.113.10"],
                    "destination_ips": [],
                    "mitre_techniques": [
                        {
                            "technique_id": "T1110",
                            "technique_name": "Brute Force",
                            "tactic": "Credential Access",
                            "reason": "Repeated failed authentication.",
                        }
                    ],
                    "attack_stages": ["CREDENTIAL_ACCESS"],
                    "timeline": [],
                    "ai_summary": "Credential access pattern.",
                    "recommended_actions": ["Reset credentials", "Block source IP"],
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
            ]
        )

        copilot_v2_service.alerts_collection = self.alerts
        copilot_v2_service.response_actions_collection = self.actions
        incident_service.alerts_collection = self.alerts
        incident_service.incidents_collection = self.incidents
        incident_service.response_actions_collection = self.actions
        incident_service.correlated_incidents_collection = QueryFakeCollection()
        attack_chain_repository.attack_chains_collection = self.chains

        self.app = FastAPI()
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
        copilot_v2_service.alerts_collection = self.originals["copilot_alerts"]
        copilot_v2_service.response_actions_collection = self.originals["copilot_actions"]
        incident_service.alerts_collection = self.originals["incident_alerts"]
        incident_service.incidents_collection = self.originals["incident_incidents"]
        incident_service.response_actions_collection = self.originals["incident_actions"]
        incident_service.correlated_incidents_collection = self.originals["incident_correlated"]
        attack_chain_repository.attack_chains_collection = self.originals["chains"]
        self.app.dependency_overrides.clear()

    async def _client(self):
        transport = httpx.ASGITransport(app=self.app)
        return httpx.AsyncClient(transport=transport, base_url="http://test")

    async def test_ask_copilot_for_incident(self):
        async with await self._client() as client:
            response = await client.post(
                "/copilot/v2/ask",
                json={
                    "incident_id": str(self.incident_id),
                    "question": "Why is this incident critical?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["context"]["context_type"], "incident")
        self.assertIn("critical", payload["short_explanation"].lower())
        self.assertIn("T1110", {item["technique_id"] for item in payload["mitre_techniques"]})
        self.assertTrue(payload["evidence_used"])
        self.assertGreater(payload["confidence_score"], 0)

    async def test_ask_copilot_for_attack_chain(self):
        async with await self._client() as client:
            response = await client.post(
                "/copilot/v2/ask",
                json={
                    "attack_chain_id": str(self.chain_id),
                    "question": "Which MITRE techniques are involved?",
                },
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["context"]["context_type"], "attack_chain")
        self.assertIn("T1110", payload["short_explanation"])

    async def test_cross_tenant_incident_access_blocked(self):
        async with await self._client() as client:
            response = await client.post(
                "/copilot/v2/ask",
                json={
                    "incident_id": str(self.other_incident_id),
                    "question": "What happened?",
                },
            )

        self.assertEqual(response.status_code, 404)

    async def test_executive_report_generated(self):
        async with await self._client() as client:
            response = await client.get(
                f"/copilot/v2/incidents/{self.incident_id}/executive-report"
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["report_type"], "executive")
        self.assertIn("Brute force against web tier", payload["title"])
        self.assertTrue(payload["recommended_actions"])

    async def test_recommended_actions_generated_for_attack_chain(self):
        async with await self._client() as client:
            response = await client.get(
                f"/copilot/v2/attack-chains/{self.chain_id}/recommended-actions"
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        actions = {item["action"] for item in payload["suggested_response_actions"]}
        self.assertIn("run_threat_hunt", actions)
        self.assertIn("block_ip", actions)

    async def test_missing_incident_returns_404(self):
        async with await self._client() as client:
            response = await client.get(
                f"/copilot/v2/incidents/{ObjectId()}/summary"
            )

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
