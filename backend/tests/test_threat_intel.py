import unittest

from bson import ObjectId
from fastapi import HTTPException

from app.services import ai_copilot_service
from app.services import threat_intel_service
from tests.test_detection_rules import FakeCollection


class ThreatIntelTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.alert_id = ObjectId()
        self.other_alert_id = ObjectId()
        self.incident_id = ObjectId()
        self.originals = {
            "ti_alerts": threat_intel_service.alerts_collection,
            "ti_incidents": threat_intel_service.incidents_collection,
            "ai_alerts": ai_copilot_service.alerts_collection,
            "ai_incidents": ai_copilot_service.incidents_collection,
            "ai_actions": ai_copilot_service.response_actions_collection,
            "ai_blocks": ai_copilot_service.security_blocks_collection,
        }
        self.alerts = FakeCollection(
            [
                {
                    "_id": self.alert_id,
                    "organization_id": "org-1",
                    "title": "Brute force",
                    "severity": "high",
                    "source_ip": "203.0.113.10",
                    "domain": "evil.example",
                    "hostname": "web-01",
                    "message": "Failed login from 203.0.113.10",
                },
                {
                    "_id": self.other_alert_id,
                    "organization_id": "org-2",
                    "source_ip": "203.0.113.10",
                },
            ]
        )
        self.incidents = FakeCollection(
            [
                {
                    "_id": self.incident_id,
                    "organization_id": "org-1",
                    "title": "Credential access",
                    "severity": "high",
                    "related_alert_ids": [str(self.alert_id)],
                }
            ]
        )
        self.empty = FakeCollection()
        threat_intel_service.alerts_collection = self.alerts
        threat_intel_service.incidents_collection = self.incidents
        ai_copilot_service.alerts_collection = self.alerts
        ai_copilot_service.incidents_collection = self.incidents
        ai_copilot_service.response_actions_collection = self.empty
        ai_copilot_service.security_blocks_collection = self.empty

    async def asyncTearDown(self):
        threat_intel_service.alerts_collection = self.originals["ti_alerts"]
        threat_intel_service.incidents_collection = self.originals["ti_incidents"]
        ai_copilot_service.alerts_collection = self.originals["ai_alerts"]
        ai_copilot_service.incidents_collection = self.originals["ai_incidents"]
        ai_copilot_service.response_actions_collection = self.originals["ai_actions"]
        ai_copilot_service.security_blocks_collection = self.originals["ai_blocks"]

    def test_lookup_known_malicious_ip(self):
        result = threat_intel_service.lookup_ioc("203.0.113.10")

        self.assertEqual(result["verdict"], "malicious")
        self.assertGreaterEqual(result["reputation_score"], 90)
        self.assertIn("brute_force", result["tags"])

    def test_unknown_indicator_safe_response(self):
        result = threat_intel_service.lookup_ioc("unknown.example")

        self.assertEqual(result["verdict"], "unknown")
        self.assertEqual(result["reputation_score"], 0)
        self.assertEqual(result["confidence"], 0)

    def test_domain_normalization(self):
        result = threat_intel_service.lookup_ioc(" Evil.Example ")

        self.assertEqual(result["normalized_indicator"], "evil.example")
        self.assertEqual(result["verdict"], "malicious")

    def test_url_domain_extraction(self):
        result = threat_intel_service.lookup_ioc("https://evil.example/login")

        self.assertEqual(result["verdict"], "malicious")
        self.assertEqual(result["type"], "domain")

    def test_bulk_lookup(self):
        result = threat_intel_service.bulk_lookup_iocs(["203.0.113.10", "unknown.example"])

        self.assertEqual(len(result["items"]), 2)
        self.assertEqual(result["items"][0]["verdict"], "malicious")
        self.assertEqual(result["items"][1]["verdict"], "unknown")

    async def test_alert_enrichment(self):
        result = await threat_intel_service.enrich_alert_threat_intel(str(self.alert_id), "org-1")

        self.assertEqual(result["threat_verdict"], "malicious")
        self.assertGreaterEqual(result["highest_reputation_score"], 90)
        self.assertTrue(result["matched_iocs"])
        self.assertEqual(result["recommended_action"], "block_ip_or_open_investigation")

    async def test_incident_enrichment(self):
        result = await threat_intel_service.enrich_incident_threat_intel(
            str(self.incident_id),
            "org-1",
        )

        self.assertEqual(result["incident_id"], str(self.incident_id))
        self.assertIn("203.0.113.10", result["malicious_source_ips"])
        self.assertIn("web-01", result["affected_assets"])
        self.assertIn("block_ip", result["recommended_actions"])

    async def test_copilot_threat_lookup_parsing(self):
        result = await ai_copilot_service.interpret_soc_query("is 8.8.8.8 malicious?", "org-1")

        self.assertEqual(result["intent"], "threat_lookup")
        self.assertEqual(result["filters"], {"indicator": "8.8.8.8"})
        self.assertEqual(result["backend_endpoint_suggestion"], "/api/threat-intel/lookup?indicator=8.8.8.8")
        self.assertEqual(result["result_preview"]["verdict"], "clean")

    async def test_copilot_threat_feed_parsing(self):
        result = await ai_copilot_service.interpret_soc_query("show malicious indicators", "org-1")

        self.assertEqual(result["intent"], "threat_feed")
        self.assertEqual(result["filters"], {"verdict": "malicious"})
        self.assertEqual(result["backend_endpoint_suggestion"], "/api/threat-intel/feed")
        self.assertGreater(result["result_preview"]["count"], 0)

    async def test_tenant_isolation(self):
        with self.assertRaises(HTTPException) as raised:
            await threat_intel_service.enrich_alert_threat_intel(str(self.other_alert_id), "org-1")

        self.assertEqual(raised.exception.status_code, 404)

    async def test_missing_alert_returns_404(self):
        with self.assertRaises(HTTPException) as raised:
            await threat_intel_service.enrich_alert_threat_intel(str(ObjectId()), "org-1")

        self.assertEqual(raised.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
