from datetime import datetime, timedelta, timezone
import unittest

from bson import ObjectId

from app.services import correlation as correlation_service
from app.services import threat_hunting as threat_hunting_service
from app.services.investigation_summary import generate_investigation_summary
from tests.test_detection_rules import FakeCollection


def alert(
    *,
    event_type="linux_ssh_failed_login",
    message="failed login",
    severity="medium",
    minutes_ago=0,
):
    return {
        "_id": ObjectId(),
        "organization_id": "org-1",
        "source": "host-a",
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "ip_address": "10.0.0.8",
        "mitre_tactic_id": "TA0006",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    }


class InvestigationCorrelationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.original_publish = correlation_service.publish_realtime_event
        self.published = []

        async def publish(event):
            self.published.append(event)

        correlation_service.publish_realtime_event = publish

    async def asyncTearDown(self):
        correlation_service.publish_realtime_event = self.original_publish

    def test_summary_mentions_failed_then_success_and_mitre(self):
        alerts = [
            alert(message="failed login", minutes_ago=3),
            alert(message="failed login", minutes_ago=2),
            alert(message="successful privileged execution", severity="high"),
        ]

        summary = generate_investigation_summary(alerts)

        self.assertIn("Multiple failed login attempts", summary)
        self.assertIn("T1110", summary)
        self.assertIn("TA0006", summary)

    async def test_correlation_groups_related_alerts(self):
        existing = [
            alert(message="failed login", minutes_ago=4),
            alert(message="failed login", minutes_ago=3),
        ]
        current = alert(
            event_type="linux_sudo_failure",
            message="successful privileged execution after sudo failures",
            severity="high",
        )
        current["mitre_tactic_id"] = "TA0004"
        current["mitre_tactic_name"] = "Privilege Escalation"
        current["mitre_technique_id"] = "T1548.003"
        current["mitre_technique_name"] = "Sudo and Sudo Caching"
        alerts_store = FakeCollection([*existing, current])
        incidents_store = FakeCollection()
        correlated_store = FakeCollection()

        group = await correlation_service.correlate_alert(
            current,
            alerts_store=alerts_store,
            incidents_store=incidents_store,
            correlated_store=correlated_store,
        )

        self.assertIsNotNone(group)
        self.assertGreaterEqual(group["correlation_score"], 45)
        self.assertEqual(len(group["related_alert_ids"]), 3)
        self.assertEqual(len(correlated_store.documents), 1)
        self.assertEqual(len(incidents_store.documents), 1)
        self.assertTrue(
            any(event["event_type"] == "correlation.created" for event in self.published)
        )
        self.assertTrue(any(event["event_type"] == "timeline.updated" for event in self.published))

    async def test_incident_timeline_returns_related_alert_events(self):
        first = alert(minutes_ago=2)
        second = alert(message="failed login accepted success", severity="high")
        incident_id = ObjectId()
        group = correlation_service.build_correlation_document(
            [first, second],
            correlation_id="corr-1",
            incident_id=str(incident_id),
        )
        incident = {
            "_id": incident_id,
            "organization_id": "org-1",
            "title": "Credential Access attack chain detected",
            "severity": "high",
            "status": "new",
            "correlation_id": "corr-1",
            "timestamp": datetime.now(timezone.utc),
        }
        originals = {
            "alerts": threat_hunting_service.alerts_collection,
            "incidents": threat_hunting_service.incidents_collection,
            "correlated": threat_hunting_service.correlated_incidents_collection,
        }
        threat_hunting_service.alerts_collection = FakeCollection([first, second])
        threat_hunting_service.incidents_collection = FakeCollection([incident])
        threat_hunting_service.correlated_incidents_collection = FakeCollection([group])
        try:
            timeline = await threat_hunting_service.incident_timeline(
                str(incident_id),
                "org-1",
            )
        finally:
            threat_hunting_service.alerts_collection = originals["alerts"]
            threat_hunting_service.incidents_collection = originals["incidents"]
            threat_hunting_service.correlated_incidents_collection = originals["correlated"]

        self.assertEqual(timeline["incident_id"], str(incident_id))
        self.assertEqual(len(timeline["events"]), 2)
        self.assertEqual(timeline["events"][0]["mitre"]["technique_id"], "T1110")
        self.assertEqual(timeline["correlated_hosts"], ["host-a"])


if __name__ == "__main__":
    unittest.main()
