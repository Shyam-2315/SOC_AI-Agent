import json
import unittest

from fastapi import HTTPException

from app.schemas.rule_pack import DetectionPackCreate, DetectionPackUpdate
from app.services import rule_packs as packs_service
from tests.test_detection_rules import DeleteResult, FakeCollection, InsertResult, UpdateResult


class FakePackCollection(FakeCollection):
    async def insert_many(self, documents):
        inserted_ids = []
        for document in documents:
            result = await self.insert_one(document)
            inserted_ids.append(result.inserted_id)
        return type("InsertManyResult", (), {"inserted_ids": inserted_ids})()

    async def update_many(self, query, update):
        count = 0
        for document in self.documents:
            if self._matches(document, query):
                document.update(update.get("$set", {}))
                count += 1
        return UpdateResult(count)

    async def delete_many(self, query):
        kept = []
        deleted = 0
        for document in self.documents:
            if self._matches(document, query):
                deleted += 1
            else:
                kept.append(document)
        self.documents = kept
        return DeleteResult(deleted)


class DetectionPackTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.user = {
            "user_id": "user-1",
            "email": "admin@example.com",
            "role": "admin",
            "organization_id": "org-1",
        }

    async def asyncSetUp(self):
        self.original_packs = packs_service.detection_rule_packs_collection
        self.original_rules = packs_service.detection_rules_collection
        self.original_audit = packs_service.write_audit_event
        self.packs = FakePackCollection()
        self.rules = FakePackCollection()
        packs_service.detection_rule_packs_collection = self.packs
        packs_service.detection_rules_collection = self.rules

        async def noop_audit(**_kwargs):
            return None

        packs_service.write_audit_event = noop_audit

    async def asyncTearDown(self):
        packs_service.detection_rule_packs_collection = self.original_packs
        packs_service.detection_rules_collection = self.original_rules
        packs_service.write_audit_event = self.original_audit

    def _pack_payload(self, name="Endpoint Starter"):
        return DetectionPackCreate(
            name=name,
            description="SOC starter rules",
            category="endpoint",
            version="1.0.0",
        )

    async def test_pack_crud(self):
        created = await packs_service.create_pack(self._pack_payload(), self.user)
        pack_id = created["pack"]["id"]

        listed = await packs_service.list_packs(
            "org-1",
            type("Pagination", (), {"limit": 20, "offset": 0})(),
        )
        updated = await packs_service.update_pack(
            pack_id,
            DetectionPackUpdate(description="Updated description"),
            self.user,
        )
        deleted = await packs_service.delete_pack(pack_id, self.user)

        self.assertEqual(listed["total"], 1)
        self.assertEqual(updated["pack"]["description"], "Updated description")
        self.assertEqual(deleted["message"], "Detection pack deleted")

    async def test_import_rules_from_json(self):
        payload = {
            "pack": {
                "name": "Imported SSH Pack",
                "description": "Imported rules",
                "category": "authentication",
                "version": "1.0.0",
            },
            "rules": [
                {
                    "title": "SSH failed login",
                    "description": "Detect SSH failed logins",
                    "level": "high",
                    "event_type": "ssh_attack",
                    "detection": {
                        "selection": {"message|contains": "failed login"},
                    },
                    "tags": ["attack.credential_access", "attack.t1110"],
                }
            ],
        }

        result = await packs_service.import_pack(
            json.dumps(payload).encode("utf-8"),
            "application/json",
            self.user,
        )

        self.assertEqual(result["pack"]["rules_count"], 1)
        self.assertEqual(len(self.rules.documents), 1)
        self.assertEqual(self.rules.documents[0]["pack_id"], result["pack"]["id"])
        self.assertEqual(self.rules.documents[0]["organization_id"], "org-1")

    async def test_export_rules_as_json_payload(self):
        imported = await packs_service.import_pack(
            json.dumps({"starter_pack": "ssh_brute_force"}).encode("utf-8"),
            "application/json",
            self.user,
        )

        exported = await packs_service.export_pack(
            imported["pack"]["id"],
            "org-1",
            self.user,
            "json",
        )

        self.assertEqual(exported["pack"]["name"], "SSH Brute Force")
        self.assertEqual(exported["rules"][0]["title"], "SSH failed login activity")
        self.assertIn("selection", exported["rules"][0]["detection"])

    async def test_import_and_export_yaml(self):
        payload = b"""
pack:
  name: YAML Network Pack
  description: YAML imported rules
  category: network
  version: 1.0.0
rules:
  - title: Suspicious outbound connection
    description: Detect suspicious outbound connection logs
    level: medium
    event_type: connection_attempt
    detection:
      selection:
        message|contains: suspicious outbound
      condition: selection
    tags:
      - attack.command_and_control
      - attack.t1071
"""
        imported = await packs_service.import_pack(payload, "application/x-yaml", self.user)

        exported = await packs_service.export_pack(
            imported["pack"]["id"],
            "org-1",
            self.user,
            "yaml",
        )

        self.assertIn("YAML Network Pack", exported)
        self.assertIn("Suspicious outbound connection", exported)

    async def test_tenant_isolation(self):
        created = await packs_service.create_pack(self._pack_payload(), self.user)

        with self.assertRaises(HTTPException) as raised:
            await packs_service.get_pack(created["pack"]["id"], "org-2")

        self.assertEqual(raised.exception.status_code, 404)

    async def test_enable_disable_cascade(self):
        imported = await packs_service.import_pack(
            json.dumps({"starter_pack": "privilege_escalation"}).encode("utf-8"),
            "application/json",
            self.user,
        )
        pack_id = imported["pack"]["id"]

        await packs_service.update_pack(
            pack_id,
            DetectionPackUpdate(enabled=False),
            self.user,
        )
        self.assertFalse(self.rules.documents[0]["enabled"])

        await packs_service.update_pack(
            pack_id,
            DetectionPackUpdate(enabled=True),
            self.user,
        )
        self.assertTrue(self.rules.documents[0]["enabled"])


if __name__ == "__main__":
    unittest.main()
