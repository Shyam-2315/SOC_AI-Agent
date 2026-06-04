import unittest
from datetime import datetime, timezone

from bson import ObjectId
from fastapi import HTTPException

from app.services import ai_copilot_service
from app.services import incidents as incidents_service
from app.services import report_generator_service
from app.services import threat_intel_service
from tests.test_detection_rules import FakeCollection


class ReportGeneratorTests(unittest.IsolatedAsyncioTestCase):
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
        self.alert_id = ObjectId()
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
                }
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

    async def test_executive_report_generation(self):
        report = await report_generator_service.generate_incident_report(
            str(self.incident_id),
            "executive",
            "org-1",
        )

        self.assertEqual(report.report_type, "executive")
        self.assertEqual(report.incident_id, str(self.incident_id))
        self.assertIsNotNone(report.generated_at)
        self.assertIn("run_threat_hunt", report.recommended_actions)
        self.assertTrue(report.sections)

    async def test_technical_report_generation(self):
        report = await report_generator_service.generate_technical_report(
            str(self.incident_id),
            "org-1",
        )

        self.assertEqual(report.report_type, "technical")
        self.assertEqual(report.incident_id, str(self.incident_id))
        self.assertEqual(report.mitre_techniques[0]["technique_id"], "T1110")
        self.assertTrue(report.timeline)
        self.assertTrue(report.soar_actions)

    async def test_compliance_report_generation(self):
        report = await report_generator_service.generate_compliance_report(
            str(self.incident_id),
            "org-1",
        )

        self.assertEqual(report.report_type, "compliance")
        self.assertEqual(report.incident_id, str(self.incident_id))
        self.assertTrue(report.matched_iocs)
        self.assertTrue(report.recommended_actions)
        self.assertIn("Analyst confirmed", report.analyst_notes)

    async def test_missing_incident_returns_404(self):
        with self.assertRaises(HTTPException) as raised:
            await report_generator_service.generate_incident_report(
                str(ObjectId()),
                "executive",
                "org-1",
            )

        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
