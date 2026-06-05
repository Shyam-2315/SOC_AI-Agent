import unittest
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from fastapi import FastAPI, HTTPException
import httpx

from app.api.dependencies import get_current_user
from app.api.routes.attack_chains import router
from app.repositories import attack_chain_repository
from app.services import attack_chain_service
from app.services.mitre_mapper import map_alert_to_mitre
from tests.test_detection_rules import AsyncCursor, DeleteResult, FakeCollection, UpdateResult


class QueryFakeCollection(FakeCollection):
    def find(self, query):
        return AsyncCursor([doc for doc in self.documents if self._matches(doc, query)])

    @staticmethod
    def _matches(document, query):
        for key, value in query.items():
            if key == "$or":
                if not any(QueryFakeCollection._matches(document, item) for item in value):
                    return False
                continue
            document_value = document.get(key)
            if isinstance(value, dict):
                if "$gte" in value and document_value < value["$gte"]:
                    return False
                if "$in" in value:
                    choices = set(value["$in"])
                    if isinstance(document_value, list):
                        if not choices.intersection(set(document_value)):
                            return False
                    elif document_value not in choices:
                        return False
                continue
            if document_value != value:
                return False
        return True

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


def alert(
    *,
    message,
    severity="medium",
    host="workstation-01",
    user="alice",
    source_ip="203.0.113.10",
    minutes=0,
):
    return {
        "_id": ObjectId(),
        "organization_id": "org-1",
        "title": message,
        "event_type": "security_alert",
        "severity": severity,
        "message": message,
        "hostname": host,
        "username": user,
        "source_ip": source_ip,
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=minutes),
    }


class MitreMapperTests(unittest.TestCase):
    def test_powershell_maps_to_t1059(self):
        mappings = map_alert_to_mitre({"message": "PowerShell EncodedCommand execution"})
        self.assertIn("T1059", {item["technique_id"] for item in mappings})

    def test_credential_dumping_maps_to_t1003(self):
        mappings = map_alert_to_mitre({"message": "Mimikatz credential dump from LSASS"})
        self.assertIn("T1003", {item["technique_id"] for item in mappings})

    def test_remote_login_lateral_movement_maps_to_t1021(self):
        mappings = map_alert_to_mitre({"message": "RDP remote login lateral movement observed"})
        self.assertIn("T1021", {item["technique_id"] for item in mappings})


class AttackChainServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "alerts": attack_chain_service.alerts_collection,
            "incidents": attack_chain_service.incidents_collection,
            "chains": attack_chain_repository.attack_chains_collection,
        }
        attack_chain_service.incidents_collection = QueryFakeCollection()
        attack_chain_repository.attack_chains_collection = QueryFakeCollection()

    async def asyncTearDown(self):
        attack_chain_service.alerts_collection = self.originals["alerts"]
        attack_chain_service.incidents_collection = self.originals["incidents"]
        attack_chain_repository.attack_chains_collection = self.originals["chains"]

    async def test_correlation_groups_alerts_from_same_host_ip_user(self):
        alerts = [
            alert(message="Suspicious login", minutes=30),
            alert(message="PowerShell execution", minutes=20),
            alert(
                message="Remote login from unrelated tenant",
                host="other-host",
                user="bob",
                source_ip="198.51.100.4",
                minutes=10,
            ),
        ]

        groups = attack_chain_service.group_related_alerts(alerts)

        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]), 2)

    async def test_risk_score_increases_with_critical_alerts(self):
        medium_chain = await attack_chain_service.build_attack_chain_from_group(
            "org-1",
            [
                alert(message="PowerShell execution", severity="medium", minutes=30),
                alert(message="RDP remote login", severity="medium", minutes=20),
            ],
        )
        critical_chain = await attack_chain_service.build_attack_chain_from_group(
            "org-1",
            [
                alert(message="PowerShell execution", severity="medium", minutes=30),
                alert(message="Mimikatz credential dump", severity="critical", minutes=20),
                alert(message="RDP lateral movement", severity="critical", minutes=10),
            ],
        )

        self.assertGreater(critical_chain["risk_score"], medium_chain["risk_score"])
        self.assertEqual(critical_chain["severity"], "critical")

    async def test_cross_tenant_access_is_blocked(self):
        chain = await attack_chain_repository.create_attack_chain(
            "org-2",
            {
                "title": "Other tenant chain",
                "status": "open",
                "severity": "high",
                "risk_score": 7.0,
                "confidence_score": 0.8,
                "related_alert_ids": [],
                "related_incident_ids": [],
                "affected_hosts": [],
                "affected_users": [],
                "source_ips": [],
                "destination_ips": [],
                "mitre_techniques": [],
                "attack_stages": [],
                "timeline": [],
                "ai_summary": "Other tenant.",
                "recommended_actions": [],
            },
        )

        with self.assertRaises(HTTPException) as raised:
            await attack_chain_repository.get_attack_chain(chain["id"], "org-1")

        self.assertEqual(raised.exception.status_code, 404)


class AttackChainRouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.originals = {
            "alerts": attack_chain_service.alerts_collection,
            "incidents": attack_chain_service.incidents_collection,
            "chains": attack_chain_repository.attack_chains_collection,
        }
        attack_chain_service.alerts_collection = QueryFakeCollection(
            [
                alert(message="Suspicious login", minutes=30),
                alert(message="PowerShell EncodedCommand execution", severity="high", minutes=20),
                alert(message="Mimikatz credential dump from LSASS", severity="critical", minutes=10),
                alert(message="SSH remote login lateral movement", severity="critical", minutes=5),
                {
                    **alert(message="Other tenant PowerShell", minutes=4),
                    "organization_id": "org-2",
                },
            ]
        )
        attack_chain_service.incidents_collection = QueryFakeCollection()
        attack_chain_repository.attack_chains_collection = QueryFakeCollection()

        self.app = FastAPI()
        self.app.include_router(router)

        async def current_user():
            return {
                "user_id": "user-1",
                "email": "analyst@example.com",
                "role": "analyst",
                "organization_id": "org-1",
                "disabled": False,
            }

        self.app.dependency_overrides[get_current_user] = current_user

    async def asyncTearDown(self):
        attack_chain_service.alerts_collection = self.originals["alerts"]
        attack_chain_service.incidents_collection = self.originals["incidents"]
        attack_chain_repository.attack_chains_collection = self.originals["chains"]
        self.app.dependency_overrides.clear()

    async def test_generate_endpoint_returns_attack_chains(self):
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/attack-chains/generate", params={"lookback_hours": 24})

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertGreaterEqual(payload["generated"], 1)
        chain = payload["items"][0]
        self.assertIn("ai_summary", chain)
        self.assertIn("T1059", {item["technique_id"] for item in chain["mitre_techniques"]})
        self.assertIn("T1003", {item["technique_id"] for item in chain["mitre_techniques"]})
        self.assertIn("T1021", {item["technique_id"] for item in chain["mitre_techniques"]})
        self.assertEqual(chain["organization_id"], "org-1")


if __name__ == "__main__":
    unittest.main()
