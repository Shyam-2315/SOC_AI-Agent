from types import SimpleNamespace
import unittest

from app.services import syslog_receiver


class SyslogReceiverTests(unittest.IsolatedAsyncioTestCase):
    def test_parse_rfc3164_message(self):
        parsed = syslog_receiver.parse_syslog_message(
            "<34>Oct 11 22:14:15 edge-fw sshd[123]: Failed password for invalid user admin from 10.0.0.9",
            "192.0.2.10",
        )

        self.assertEqual(parsed.priority, 34)
        self.assertEqual(parsed.hostname, "edge-fw")
        self.assertEqual(parsed.program, "sshd")
        self.assertEqual(parsed.source_ip, "192.0.2.10")
        self.assertIn("Failed password", parsed.message)

    def test_parse_rfc5424_message(self):
        parsed = syslog_receiver.parse_syslog_message(
            "<11>1 2026-05-13T10:00:00Z host1 sudo 123 ID47 - sudo failure for analyst",
            "203.0.113.7",
        )

        self.assertEqual(parsed.priority, 11)
        self.assertEqual(parsed.timestamp, "2026-05-13T10:00:00Z")
        self.assertEqual(parsed.hostname, "host1")
        self.assertEqual(parsed.program, "sudo")
        self.assertEqual(parsed.message, "sudo failure for analyst")

    def test_priority_maps_to_soc_severity(self):
        self.assertEqual(syslog_receiver.syslog_priority_to_severity(10), "critical")
        self.assertEqual(syslog_receiver.syslog_priority_to_severity(11), "high")
        self.assertEqual(syslog_receiver.syslog_priority_to_severity(12), "medium")
        self.assertEqual(syslog_receiver.syslog_priority_to_severity(14), "low")
        self.assertEqual(syslog_receiver.syslog_priority_to_severity(None), "low")

    def test_collector_conversion_uses_hostname_and_source_ip(self):
        parsed = syslog_receiver.parse_syslog_message(
            "<10>Oct 11 22:14:15 linux-1 kernel: critical event",
            "198.51.100.4",
        )

        log = syslog_receiver.syslog_to_collector_log(parsed)

        self.assertEqual(log["source"], "linux-1")
        self.assertEqual(log["event_type"], "syslog_event")
        self.assertEqual(log["severity"], "critical")
        self.assertEqual(log["ip_address"], "198.51.100.4")
        self.assertIn("program=kernel", log["message"])

    async def test_batch_ingestion_uses_syslog_collector_token_org(self):
        originals = {
            "settings": syslog_receiver.settings,
            "auth": syslog_receiver.authenticate_collector_token,
            "ingest": syslog_receiver.ingest_collector_batch,
        }
        seen = {}

        async def fake_auth(token):
            seen["token"] = token
            return {"_id": "collector-1", "organization_id": "org-syslog"}

        async def fake_ingest(batch, collector):
            seen["organization_id"] = collector["organization_id"]
            seen["event_type"] = batch.logs[0]["event_type"]
            return {"accepted": 1, "rejected": 0}

        syslog_receiver.settings = SimpleNamespace(
            syslog_enabled=True,
            syslog_collector_token="syslog-token",
            syslog_host="127.0.0.1",
            syslog_port=5514,
            collector_batch_max_size=10,
        )
        syslog_receiver.authenticate_collector_token = fake_auth
        syslog_receiver.ingest_collector_batch = fake_ingest
        try:
            collector = await syslog_receiver.authenticate_collector_token(
                syslog_receiver.settings.syslog_collector_token
            )
            log = syslog_receiver.syslog_to_collector_log(
                syslog_receiver.parse_syslog_message("<14>host app: message", "10.0.0.1")
            )
            await syslog_receiver.ingest_collector_batch(
                syslog_receiver.CollectorIngestBatch(logs=[log]),
                collector,
            )
        finally:
            syslog_receiver.settings = originals["settings"]
            syslog_receiver.authenticate_collector_token = originals["auth"]
            syslog_receiver.ingest_collector_batch = originals["ingest"]

        self.assertEqual(seen["token"], "syslog-token")
        self.assertEqual(seen["organization_id"], "org-syslog")
        self.assertEqual(seen["event_type"], "syslog_event")


if __name__ == "__main__":
    unittest.main()
