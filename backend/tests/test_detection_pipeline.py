from types import SimpleNamespace
import unittest

from bson import ObjectId

from app.schemas.collector import CollectorIngestBatch
from app.services import collectors as collectors_service
from app.services import ingestion as ingestion_service
from app.services import rules as rules_service
from tests.test_detection_rules import FakeCollection


class DetectionPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "collector_ingest_log": collectors_service.ingest_log,
            "collector_settings": collectors_service.settings,
            "collector_collection": collectors_service.collectors_collection,
            "rules_collection": rules_service.detection_rules_collection,
            "logs": ingestion_service.logs_collection,
            "alerts": ingestion_service.alerts_collection,
            "actions": ingestion_service.response_actions_collection,
            "incidents": ingestion_service.incidents_collection,
            "audit": ingestion_service.write_audit_event,
            "campaign": ingestion_service.detect_attack_campaign,
            "publish": ingestion_service.publish_realtime_event,
            "settings": ingestion_service.settings,
        }
        self.rules = FakeCollection()
        self.logs = FakeCollection()
        self.alerts = FakeCollection()
        self.actions = FakeCollection()
        self.incidents = FakeCollection()
        self.collectors = FakeCollection()
        self.published_events = []

        collectors_service.settings = SimpleNamespace(collector_batch_max_size=10)
        collectors_service.collectors_collection = self.collectors
        rules_service.detection_rules_collection = self.rules
        ingestion_service.logs_collection = self.logs
        ingestion_service.alerts_collection = self.alerts
        ingestion_service.response_actions_collection = self.actions
        ingestion_service.incidents_collection = self.incidents
        ingestion_service.settings = SimpleNamespace(celery_enabled=True)

        async def noop_audit(**_kwargs):
            return None

        async def campaign(*_args):
            return {"campaign_detected": False}

        async def publish(event):
            self.published_events.append(event)

        ingestion_service.write_audit_event = noop_audit
        ingestion_service.detect_attack_campaign = campaign
        ingestion_service.publish_realtime_event = publish

    async def asyncTearDown(self):
        collectors_service.ingest_log = self.originals["collector_ingest_log"]
        collectors_service.settings = self.originals["collector_settings"]
        collectors_service.collectors_collection = self.originals["collector_collection"]
        rules_service.detection_rules_collection = self.originals["rules_collection"]
        ingestion_service.logs_collection = self.originals["logs"]
        ingestion_service.alerts_collection = self.originals["alerts"]
        ingestion_service.response_actions_collection = self.originals["actions"]
        ingestion_service.incidents_collection = self.originals["incidents"]
        ingestion_service.write_audit_event = self.originals["audit"]
        ingestion_service.detect_attack_campaign = self.originals["campaign"]
        ingestion_service.publish_realtime_event = self.originals["publish"]
        ingestion_service.settings = self.originals["settings"]

    async def _insert_rule(
        self,
        *,
        organization_id="org-1",
        enabled=True,
        value="failed login",
    ):
        rule = {
            "_id": ObjectId(),
            "name": "SSH failed login",
            "description": "Detect SSH failed logins",
            "severity": "high",
            "event_type": "ssh_login",
            "conditions": [
                {"field": "message", "operator": "contains", "value": value},
                {"field": "severity", "operator": "equals", "value": "low"},
            ],
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 - Brute Force",
            "enabled": enabled,
            "organization_id": organization_id,
        }
        await self.rules.insert_one(rule)
        return rule

    def _collector(self, organization_id="org-1"):
        return {
            "_id": ObjectId(),
            "name": "Linux collector",
            "status": "active",
            "organization_id": organization_id,
        }

    async def _ingest(self, organization_id="org-1", message="failed login from host"):
        return await collectors_service.ingest_collector_batch(
            CollectorIngestBatch(
                logs=[
                    {
                        "source": "linux",
                        "event_type": "ssh_login",
                        "severity": "low",
                        "message": message,
                        "ip_address": "10.0.0.5",
                    }
                ],
            ),
            self._collector(organization_id),
        )

    async def test_matching_rule_creates_alert(self):
        await self._insert_rule()

        response = await self._ingest()

        self.assertEqual(response["accepted"], 1)
        self.assertEqual(response["results"][0]["alert_generated"], True)
        self.assertEqual(len(self.alerts.documents), 1)
        self.assertEqual(self.alerts.documents[0]["organization_id"], "org-1")
        self.assertEqual(self.alerts.documents[0]["matched_rule_name"], "SSH failed login")
        self.assertEqual(self.alerts.documents[0]["severity"], "high")
        self.assertTrue(
            any(event["event_type"] == "soc.alert.created" for event in self.published_events)
        )

    async def test_non_matching_rule_does_not_create_alert(self):
        await self._insert_rule(value="impossible marker")

        response = await self._ingest(message="routine login from host")

        self.assertEqual(response["accepted"], 1)
        self.assertEqual(response["results"][0]["alert_generated"], False)
        self.assertEqual(len(self.alerts.documents), 0)
        self.assertEqual(len(self.published_events), 0)

    async def test_disabled_rule_does_not_create_alert(self):
        await self._insert_rule(enabled=False)

        response = await self._ingest()

        self.assertEqual(response["accepted"], 1)
        self.assertEqual(response["results"][0]["alert_generated"], False)
        self.assertEqual(len(self.alerts.documents), 0)

    async def test_alert_belongs_to_same_organization_only(self):
        await self._insert_rule(organization_id="org-2")

        response = await self._ingest(organization_id="org-1")

        self.assertEqual(response["accepted"], 1)
        self.assertEqual(response["results"][0]["alert_generated"], False)
        self.assertEqual(len(self.alerts.documents), 0)


if __name__ == "__main__":
    unittest.main()
