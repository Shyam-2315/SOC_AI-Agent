import unittest
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import HTTPException

from app.services import ai_copilot_service
from tests.test_detection_rules import FakeCollection


class AiCopilotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "alerts": ai_copilot_service.alerts_collection,
            "incidents": ai_copilot_service.incidents_collection,
            "actions": ai_copilot_service.response_actions_collection,
            "blocks": ai_copilot_service.security_blocks_collection,
        }
        self.alert_id = ObjectId()
        self.other_alert_id = ObjectId()
        self.incident_id = ObjectId()
        self.alerts = FakeCollection(
            [
                {
                    "_id": self.alert_id,
                    "organization_id": "org-1",
                    "title": "Windows Failed Login Detected",
                    "event_type": "windows_failed_login",
                    "severity": "high",
                    "message": "Repeated failed login from 203.0.113.10",
                    "ip_address": "203.0.113.10",
                    "source_ip": "203.0.113.10",
                    "hostname": "web-01",
                    "username": "admin",
                    "failed_login_count": 7,
                    "matched_rule_id": "rule-1",
                    "matched_rule_name": "Brute force login",
                    "rule_confidence": 0.9,
                    "mitre_tactic_id": "TA0006",
                    "mitre_tactic_name": "Credential Access",
                    "mitre_technique_id": "T1110",
                    "mitre_technique_name": "Brute Force",
                    "timestamp": datetime.now(timezone.utc),
                },
                {
                    "_id": ObjectId(),
                    "organization_id": "org-1",
                    "event_type": "windows_failed_login",
                    "severity": "medium",
                    "ip_address": "203.0.113.10",
                    "hostname": "web-02",
                    "message": "Repeated failed login",
                    "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
                },
                {
                    "_id": self.other_alert_id,
                    "organization_id": "org-2",
                    "event_type": "windows_failed_login",
                    "severity": "critical",
                    "ip_address": "203.0.113.10",
                    "hostname": "web-99",
                },
            ]
        )
        self.incidents = FakeCollection(
            [
                {
                    "_id": self.incident_id,
                    "organization_id": "org-1",
                    "title": "Brute force against web tier",
                    "description": "Credential attack",
                    "severity": "high",
                    "status": "new",
                    "related_alert_ids": [str(self.alert_id)],
                    "timestamp": datetime.now(timezone.utc),
                },
                {
                    "_id": ObjectId(),
                    "organization_id": "org-2",
                    "title": "Other tenant incident",
                    "severity": "critical",
                },
            ]
        )
        self.actions = FakeCollection(
            [
                {
                    "_id": ObjectId(),
                    "organization_id": "org-1",
                    "ip_address": "203.0.113.10",
                    "action_type": "block_ip",
                    "automated_actions": ["Blocked malicious IP: 203.0.113.10"],
                    "timestamp": datetime.now(timezone.utc),
                }
            ]
        )
        self.blocks = FakeCollection()
        ai_copilot_service.alerts_collection = self.alerts
        ai_copilot_service.incidents_collection = self.incidents
        ai_copilot_service.response_actions_collection = self.actions
        ai_copilot_service.security_blocks_collection = self.blocks

    async def asyncTearDown(self):
        ai_copilot_service.alerts_collection = self.originals["alerts"]
        ai_copilot_service.incidents_collection = self.originals["incidents"]
        ai_copilot_service.response_actions_collection = self.originals["actions"]
        ai_copilot_service.security_blocks_collection = self.originals["blocks"]

    async def test_alert_triage_output(self):
        result = await ai_copilot_service.triage_alert(str(self.alert_id), "org-1")

        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertIn(result["priority"], {"high", "critical"})
        self.assertEqual(result["recommended_action"], "block_ip")
        self.assertEqual(result["mapped_mitre_techniques"][0]["technique_id"], "T1110")
        self.assertTrue(any("Failed-login" in reason for reason in result["reasoning"]))

    async def test_incident_summary_output(self):
        result = await ai_copilot_service.summarize_incident(str(self.incident_id), "org-1")

        self.assertEqual(result["title"], "Brute force against web tier")
        self.assertIn("web-01", result["affected_assets"])
        self.assertEqual(result["mitre_techniques"][0]["technique_id"], "T1110")
        self.assertIn("run_threat_hunt", result["recommended_actions"])
        self.assertTrue(result["analyst_next_steps"])

    async def test_false_positive_score_output(self):
        result = await ai_copilot_service.score_false_positive(str(self.alert_id), "org-1")

        self.assertLess(result["false_positive_score"], 50)
        self.assertEqual(result["suggested_status"], "investigate")
        self.assertIn(result["confidence"], {"medium", "high"})
        self.assertTrue(result["reasons"])

    async def test_recommended_actions_output(self):
        result = await ai_copilot_service.recommend_actions_for_incident(
            str(self.incident_id),
            "org-1",
        )

        self.assertEqual(result["incident_id"], str(self.incident_id))
        self.assertIn("open_investigation", result["recommended_actions"])
        self.assertIn("run_threat_hunt", result["recommended_actions"])
        self.assertTrue(result["reasons"])

    async def test_natural_language_query_parsing(self):
        result = await ai_copilot_service.interpret_soc_query(
            "show MITRE T1110 activity",
            "org-1",
        )

        self.assertEqual(result["intent"], "show_mitre_activity")
        self.assertEqual(result["filters"]["mitre_technique_id"], "T1110")
        self.assertIn("/alerts/", result["backend_endpoint_suggestion"])
        self.assertEqual(result["result_preview"]["count"], 1)

    async def test_tenant_isolation(self):
        with self.assertRaises(HTTPException) as raised:
            await ai_copilot_service.triage_alert(str(self.other_alert_id), "org-1")

        self.assertEqual(raised.exception.status_code, 404)

    async def test_missing_alert_returns_404(self):
        with self.assertRaises(HTTPException) as raised:
            await ai_copilot_service.triage_alert(str(ObjectId()), "org-1")

        self.assertEqual(raised.exception.status_code, 404)

    async def test_missing_incident_returns_404(self):
        with self.assertRaises(HTTPException) as raised:
            await ai_copilot_service.summarize_incident(str(ObjectId()), "org-1")

        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
