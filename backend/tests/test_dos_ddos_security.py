from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from bson import ObjectId
from fastapi import FastAPI
import httpx

from app.core.middleware import TrafficProtectionMiddleware
from app.services import blocklist_service
from app.services import dos_ddos_detection_service as security_service


class InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class UpdateResult:
    def __init__(self, matched_count, upserted_id=None):
        self.matched_count = matched_count
        self.upserted_id = upserted_id


class AsyncCursor:
    def __init__(self, documents):
        self.documents = list(documents)

    def sort(self, field, direction):
        reverse = direction < 0
        self.documents.sort(key=lambda item: item.get(field) or datetime.min.replace(tzinfo=timezone.utc), reverse=reverse)
        return self

    def limit(self, limit):
        self.documents = self.documents[:limit]
        return self

    def __aiter__(self):
        self._index = 0
        return self

    async def __anext__(self):
        if self._index >= len(self.documents):
            raise StopAsyncIteration
        item = self.documents[self._index]
        self._index += 1
        return dict(item)


class FakeCollection:
    def __init__(self, documents=None):
        self.documents = list(documents or [])

    async def insert_one(self, document):
        inserted = dict(document)
        inserted.setdefault("_id", ObjectId())
        self.documents.append(inserted)
        return InsertResult(inserted["_id"])

    async def update_one(self, query, update, upsert=False):
        for document in self.documents:
            if self._matches(document, query):
                document.update(update.get("$set", {}))
                return UpdateResult(1)
        if upsert:
            inserted = dict(query)
            inserted.update(update.get("$set", {}))
            inserted.setdefault("_id", ObjectId())
            self.documents.append(inserted)
            return UpdateResult(0, inserted["_id"])
        return UpdateResult(0)

    async def find_one(self, query):
        for document in self.documents:
            if self._matches(document, query):
                return dict(document)
        return None

    def find(self, query):
        return AsyncCursor([doc for doc in self.documents if self._matches(doc, query)])

    @staticmethod
    def _matches(document, query):
        for key, value in query.items():
            if key == "$or":
                if not any(FakeCollection._matches(document, candidate) for candidate in value):
                    return False
                continue
            if isinstance(value, dict) and "$nin" in value:
                if document.get(key) in value["$nin"]:
                    return False
                continue
            if document.get(key) != value:
                return False
        return True


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.sets = {}
        self.sorted = {}

    async def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    async def expire(self, key, _seconds):
        return True

    async def get(self, key):
        return self.values.get(key)

    async def sadd(self, key, value):
        self.sets.setdefault(key, set()).add(value)
        return 1

    async def scard(self, key):
        return len(self.sets.get(key, set()))

    async def set(self, key, value, ex=None, nx=False):
        _ = ex
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def exists(self, key):
        return 1 if key in self.values else 0

    async def delete(self, key):
        self.values.pop(key, None)
        return 1

    async def zincrby(self, key, amount, member):
        self.sorted.setdefault(key, {})
        self.sorted[key][member] = self.sorted[key].get(member, 0) + amount
        return self.sorted[key][member]

    async def zrevrange(self, key, start, stop, withscores=False):
        items = sorted(self.sorted.get(key, {}).items(), key=lambda item: item[1], reverse=True)
        sliced = items[start : stop + 1]
        if withscores:
            return sliced
        return [member for member, _score in sliced]


class DosDdosSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "settings": security_service.settings,
            "alerts": security_service.alerts_collection,
            "incidents": security_service.incidents_collection,
            "actions": security_service.response_actions_collection,
            "detections": security_service.security_detections_collection,
            "orgs": security_service.organizations_collection,
            "audit": security_service.write_audit_event,
            "publish": security_service.publish_realtime_event,
            "redis": security_service.get_redis_client,
            "blocklist_collection": blocklist_service.security_blocks_collection,
            "blocklist_redis": blocklist_service.get_redis_client,
        }
        self.redis = FakeRedis()
        self.alerts = FakeCollection()
        self.incidents = FakeCollection()
        self.actions = FakeCollection()
        self.detections = FakeCollection()
        self.orgs = FakeCollection([{"_id": ObjectId("507f1f77bcf86cd799439011"), "name": "Demo"}])
        self.blocks = FakeCollection()
        self.events = []

        security_service.settings = SimpleNamespace(
            dos_ip_requests_per_minute=3,
            dos_ip_errors_per_minute=2,
            ddos_endpoint_requests_per_minute=5,
            ddos_endpoint_unique_ips_per_minute=3,
            auto_block_dos_ips=False,
        )
        security_service.alerts_collection = self.alerts
        security_service.incidents_collection = self.incidents
        security_service.response_actions_collection = self.actions
        security_service.security_detections_collection = self.detections
        security_service.organizations_collection = self.orgs
        security_service.get_redis_client = self._get_redis
        blocklist_service.security_blocks_collection = self.blocks
        blocklist_service.get_redis_client = self._get_redis

        async def noop_audit(**_kwargs):
            return None

        async def publish(event):
            self.events.append(event)

        security_service.write_audit_event = noop_audit
        security_service.publish_realtime_event = publish

    async def asyncTearDown(self):
        security_service.settings = self.originals["settings"]
        security_service.alerts_collection = self.originals["alerts"]
        security_service.incidents_collection = self.originals["incidents"]
        security_service.response_actions_collection = self.originals["actions"]
        security_service.security_detections_collection = self.originals["detections"]
        security_service.organizations_collection = self.originals["orgs"]
        security_service.write_audit_event = self.originals["audit"]
        security_service.publish_realtime_event = self.originals["publish"]
        security_service.get_redis_client = self.originals["redis"]
        blocklist_service.security_blocks_collection = self.originals["blocklist_collection"]
        blocklist_service.get_redis_client = self.originals["blocklist_redis"]

    async def _get_redis(self):
        return self.redis

    async def test_ip_exceeding_threshold_creates_dos_alert(self):
        for _ in range(3):
            await security_service.process_traffic_event(
                source_ip="198.51.100.10",
                path="/login",
                method="GET",
                status_code=200,
                user_agent="test",
                organization_id="org-1",
            )

        self.assertEqual(len(self.alerts.documents), 1)
        self.assertEqual(self.alerts.documents[0]["event_type"], "dos_attack")
        self.assertEqual(self.alerts.documents[0]["target_path"], "/login")

    async def test_endpoint_exceeding_unique_ip_threshold_creates_ddos_alert(self):
        for ip in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            await security_service.process_traffic_event(
                source_ip=ip,
                path="/alerts/",
                method="GET",
                status_code=200,
                user_agent="test",
                organization_id="org-1",
            )

        ddos_alerts = [doc for doc in self.alerts.documents if doc["event_type"] == "ddos_attack"]
        self.assertEqual(len(ddos_alerts), 1)
        self.assertEqual(ddos_alerts[0]["target_path"], "/alerts/")
        self.assertTrue(any("DDoS Activity Targeting /alerts/" == doc["title"] for doc in self.incidents.documents))

    async def test_auto_block_disabled_creates_alert_only(self):
        security_service.settings.auto_block_dos_ips = False
        for _ in range(3):
            await security_service.process_traffic_event(
                source_ip="203.0.113.8",
                path="/rules",
                method="GET",
                status_code=429,
                user_agent="test",
                organization_id="org-1",
            )

        self.assertEqual(len(self.alerts.documents), 1)
        self.assertFalse(await blocklist_service.is_blocked("203.0.113.8"))

    async def test_auto_block_enabled_blocks_ip(self):
        security_service.settings.auto_block_dos_ips = True
        for _ in range(3):
            await security_service.process_traffic_event(
                source_ip="203.0.113.20",
                path="/incidents/",
                method="GET",
                status_code=503,
                user_agent="test",
                organization_id="org-1",
            )

        self.assertTrue(await blocklist_service.is_blocked("203.0.113.20"))
        self.assertEqual(self.actions.documents[0]["status"], "simulated")

    async def test_blocked_ip_receives_403_and_health_endpoint_still_works(self):
        original_is_blocked = TrafficProtectionMiddleware.dispatch.__globals__["is_blocked"]
        original_process = TrafficProtectionMiddleware.dispatch.__globals__["process_traffic_event"]

        async def fake_is_blocked(ip):
            return ip == "203.0.113.99"

        async def fake_process_traffic_event(**_kwargs):
            return None

        TrafficProtectionMiddleware.dispatch.__globals__["is_blocked"] = fake_is_blocked
        TrafficProtectionMiddleware.dispatch.__globals__["process_traffic_event"] = (
            fake_process_traffic_event
        )
        try:
            app = FastAPI()
            app.add_middleware(TrafficProtectionMiddleware)

            @app.get("/protected")
            async def protected():
                return {"ok": True}

            @app.get("/health")
            async def health():
                return {"status": "ok"}

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                blocked = await client.get(
                    "/protected",
                    headers={"x-forwarded-for": "203.0.113.99"},
                )
                health = await client.get(
                    "/health",
                    headers={"x-forwarded-for": "203.0.113.99"},
                )
        finally:
            TrafficProtectionMiddleware.dispatch.__globals__["is_blocked"] = original_is_blocked
            TrafficProtectionMiddleware.dispatch.__globals__["process_traffic_event"] = (
                original_process
            )

        self.assertEqual(blocked.status_code, 403)
        self.assertEqual(blocked.json()["error"]["code"], "traffic_blocked")
        self.assertEqual(
            blocked.json()["error"]["message"],
            "Request blocked due to suspicious traffic behavior",
        )
        self.assertEqual(health.status_code, 200)


if __name__ == "__main__":
    unittest.main()
