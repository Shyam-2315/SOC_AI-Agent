from types import SimpleNamespace
import unittest

from bson import ObjectId
from fastapi import HTTPException

from app.schemas.log import LogModel
from app.schemas.rule import DetectionRuleCreate, DetectionRuleUpdate, RuleCondition
from app.services import ingestion as ingestion_service
from app.services import rules as rules_service


class InsertResult:
    def __init__(self, inserted_id):
        self.inserted_id = inserted_id


class UpdateResult:
    def __init__(self, matched_count):
        self.matched_count = matched_count


class DeleteResult:
    def __init__(self, deleted_count):
        self.deleted_count = deleted_count


class AsyncCursor:
    def __init__(self, documents):
        self.documents = list(documents)

    def sort(self, *_args):
        return self

    def skip(self, offset):
        self.documents = self.documents[offset:]
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

    def find(self, query):
        return AsyncCursor([doc for doc in self.documents if self._matches(doc, query)])

    async def find_one(self, query):
        for doc in self.documents:
            if self._matches(doc, query):
                return dict(doc)
        return None

    async def count_documents(self, query):
        return len([doc for doc in self.documents if self._matches(doc, query)])

    async def update_one(self, query, update):
        for doc in self.documents:
            if self._matches(doc, query):
                doc.update(update.get("$set", {}))
                return UpdateResult(1)
        return UpdateResult(0)

    async def delete_one(self, query):
        for index, doc in enumerate(self.documents):
            if self._matches(doc, query):
                self.documents.pop(index)
                return DeleteResult(1)
        return DeleteResult(0)

    @staticmethod
    def _matches(document, query):
        return all(document.get(key) == value for key, value in query.items())


class DetectionRuleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.user = {
            "user_id": "user-1",
            "email": "admin@example.com",
            "role": "admin",
            "organization_id": "org-1",
        }

    async def asyncSetUp(self):
        self.original_rules_collection = rules_service.detection_rules_collection
        self.original_audit = rules_service.write_audit_event
        self.rules_collection = FakeCollection()
        rules_service.detection_rules_collection = self.rules_collection

        async def noop_audit(**_kwargs):
            return None

        rules_service.write_audit_event = noop_audit

    async def asyncTearDown(self):
        rules_service.detection_rules_collection = self.original_rules_collection
        rules_service.write_audit_event = self.original_audit

    def _rule_payload(self, name="Critical SSH"):
        return DetectionRuleCreate(
            name=name,
            description="Detect critical SSH activity",
            severity="high",
            event_type="ssh_attack",
            conditions=[
                RuleCondition(field="message", operator="contains", value="failed login"),
                RuleCondition(field="severity", operator="equals", value="medium"),
            ],
            mitre_tactic="Credential Access",
            mitre_technique="T1110 - Brute Force",
            enabled=True,
        )

    async def test_rule_creation(self):
        result = await rules_service.create_rule(self._rule_payload(), self.user)

        self.assertEqual(result["rule"]["name"], "Critical SSH")
        self.assertEqual(result["rule"]["organization_id"], "org-1")
        self.assertEqual(len(self.rules_collection.documents), 1)

    async def test_rule_update(self):
        created = await rules_service.create_rule(self._rule_payload(), self.user)
        rule_id = created["rule"]["id"]

        result = await rules_service.update_rule(
            rule_id,
            DetectionRuleUpdate(enabled=False, severity="critical"),
            self.user,
        )

        self.assertFalse(result["rule"]["enabled"])
        self.assertEqual(result["rule"]["severity"], "critical")

    async def test_rule_deletion(self):
        created = await rules_service.create_rule(self._rule_payload(), self.user)

        result = await rules_service.delete_rule(created["rule"]["id"], self.user)

        self.assertEqual(result["message"], "Rule deleted")
        self.assertEqual(len(self.rules_collection.documents), 0)

    async def test_tenant_isolation(self):
        created = await rules_service.create_rule(self._rule_payload(), self.user)

        with self.assertRaises(HTTPException) as raised:
            await rules_service.get_rule(created["rule"]["id"], "other-org")

        self.assertEqual(raised.exception.status_code, 404)

    async def test_rule_matching_during_ingestion(self):
        created = await rules_service.create_rule(self._rule_payload(), self.user)
        originals = {
            "rules_collection": rules_service.detection_rules_collection,
            "ingest_evaluate_rules": ingestion_service.evaluate_rules,
            "logs": ingestion_service.logs_collection,
            "alerts": ingestion_service.alerts_collection,
            "actions": ingestion_service.response_actions_collection,
            "incidents": ingestion_service.incidents_collection,
            "audit": ingestion_service.write_audit_event,
            "campaign": ingestion_service.detect_attack_campaign,
            "publish": ingestion_service.publish_realtime_event,
            "settings": ingestion_service.settings,
        }
        logs = FakeCollection()
        alerts = FakeCollection()
        actions = FakeCollection()
        incidents = FakeCollection()

        async def local_evaluate(log_context):
            return await rules_service.evaluate_rules(log_context)

        async def noop_audit(**_kwargs):
            return None

        async def campaign(*_args):
            return {"campaign_detected": False}

        async def publish(_event):
            return None

        ingestion_service.evaluate_rules = local_evaluate
        ingestion_service.logs_collection = logs
        ingestion_service.alerts_collection = alerts
        ingestion_service.response_actions_collection = actions
        ingestion_service.incidents_collection = incidents
        ingestion_service.write_audit_event = noop_audit
        ingestion_service.detect_attack_campaign = campaign
        ingestion_service.publish_realtime_event = publish
        ingestion_service.settings = SimpleNamespace(celery_enabled=False)
        try:
            result = await ingestion_service.ingest_log(
                LogModel(
                    source="linux",
                    event_type="ssh_attack",
                    severity="medium",
                    message="Repeated failed login from external host",
                    ip_address="10.0.0.4",
                ),
                "org-1",
            )
        finally:
            ingestion_service.evaluate_rules = originals["ingest_evaluate_rules"]
            ingestion_service.logs_collection = originals["logs"]
            ingestion_service.alerts_collection = originals["alerts"]
            ingestion_service.response_actions_collection = originals["actions"]
            ingestion_service.incidents_collection = originals["incidents"]
            ingestion_service.write_audit_event = originals["audit"]
            ingestion_service.detect_attack_campaign = originals["campaign"]
            ingestion_service.publish_realtime_event = originals["publish"]
            ingestion_service.settings = originals["settings"]

        self.assertTrue(result["alert_generated"])
        self.assertEqual(result["matched_rule"]["id"], created["rule"]["id"])
        self.assertEqual(alerts.documents[0]["matched_rule_name"], "Critical SSH")
        self.assertEqual(alerts.documents[0]["severity"], "high")
        self.assertEqual(len(incidents.documents), 1)


if __name__ == "__main__":
    unittest.main()
