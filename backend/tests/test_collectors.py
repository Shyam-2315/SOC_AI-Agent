from types import SimpleNamespace
import unittest

from fastapi import HTTPException

from app.schemas.collector import CollectorCreate, CollectorIngestBatch, CollectorUpdate
from app.services import collectors as collectors_service
from tests.test_detection_rules import FakeCollection


class CollectorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.user = {
            "user_id": "user-1",
            "email": "admin@example.com",
            "role": "admin",
            "organization_id": "org-1",
        }

    async def asyncSetUp(self):
        self.original_collection = collectors_service.collectors_collection
        self.original_audit = collectors_service.write_audit_event
        self.original_ingest = collectors_service.ingest_log
        self.original_settings = collectors_service.settings
        self.collection = FakeCollection()
        collectors_service.collectors_collection = self.collection
        collectors_service.settings = SimpleNamespace(collector_batch_max_size=10)

        async def noop_audit(**_kwargs):
            return None

        collectors_service.write_audit_event = noop_audit

    async def asyncTearDown(self):
        collectors_service.collectors_collection = self.original_collection
        collectors_service.write_audit_event = self.original_audit
        collectors_service.ingest_log = self.original_ingest
        collectors_service.settings = self.original_settings

    async def _create_collector(self, name="Linux Agent"):
        return await collectors_service.create_collector(
            CollectorCreate(name=name, type="linux"),
            self.user,
        )

    async def test_collector_create_hashes_token_at_rest(self):
        result = await self._create_collector()

        self.assertEqual(result["collector"]["name"], "Linux Agent")
        self.assertIn("api_key", result)
        stored = self.collection.documents[0]
        self.assertNotEqual(stored["api_key_hash"], result["api_key"])
        self.assertEqual(stored["organization_id"], "org-1")

    async def test_collector_token_auth_maps_to_collector_and_organization(self):
        result = await self._create_collector()

        collector = await collectors_service.authenticate_collector_token(
            result["api_key"]
        )

        self.assertEqual(collector["name"], "Linux Agent")
        self.assertEqual(collector["organization_id"], "org-1")

    async def test_batch_ingestion_accepts_valid_logs_and_uses_collector_org(self):
        result = await self._create_collector()
        collector = await collectors_service.authenticate_collector_token(
            result["api_key"]
        )
        seen = {}

        async def fake_ingest(log, organization_id, **_kwargs):
            seen["organization_id"] = organization_id
            seen["event_type"] = log.event_type
            return {
                "log_id": "log-1",
                "alert_generated": False,
                "matched_rule": None,
            }

        collectors_service.ingest_log = fake_ingest
        response = await collectors_service.ingest_collector_batch(
            CollectorIngestBatch(
                logs=[
                    {
                        "source": "linux-agent",
                        "event_type": "ssh_login",
                        "severity": "low",
                        "message": "Accepted login",
                        "ip_address": "10.0.0.5",
                    },
                    {
                        "source": "linux-agent",
                        "event_type": "bad",
                        "severity": "low",
                        "message": "Missing IP should be rejected",
                    },
                ]
            ),
            collector,
        )

        self.assertEqual(response["accepted"], 1)
        self.assertEqual(response["rejected"], 1)
        self.assertEqual(seen["organization_id"], "org-1")
        self.assertEqual(seen["event_type"], "ssh_login")
        self.assertIsNotNone(self.collection.documents[0]["last_seen_at"])

    async def test_tenant_isolation_on_update(self):
        result = await self._create_collector()
        other_user = {**self.user, "organization_id": "org-2"}

        with self.assertRaises(HTTPException) as raised:
            await collectors_service.update_collector(
                result["collector"]["id"],
                CollectorUpdate(name="Other Tenant Update"),
                other_user,
            )

        self.assertEqual(raised.exception.status_code, 404)

    async def test_disabled_collector_is_rejected(self):
        result = await self._create_collector()
        await collectors_service.update_collector(
            result["collector"]["id"],
            CollectorUpdate(status="disabled"),
            self.user,
        )

        with self.assertRaises(HTTPException) as raised:
            await collectors_service.authenticate_collector_token(result["api_key"])

        self.assertEqual(raised.exception.status_code, 403)

    async def test_collector_delete_removes_only_same_tenant(self):
        result = await self._create_collector()

        delete_response = await collectors_service.delete_collector(
            result["collector"]["id"],
            self.user,
        )

        self.assertEqual(delete_response["message"], "Collector deleted")
        self.assertEqual(len(self.collection.documents), 0)


if __name__ == "__main__":
    unittest.main()
