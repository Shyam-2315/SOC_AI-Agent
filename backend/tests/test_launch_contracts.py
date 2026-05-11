from types import SimpleNamespace
import unittest

from fastapi import HTTPException
from pydantic import ValidationError

from app.api.dependencies import get_collector_organization_id
from app.schemas.copilot import CopilotQuery
from app.schemas.log import LogModel
from app.services import auth as auth_service


class LaunchContractTests(unittest.IsolatedAsyncioTestCase):
    def test_copilot_accepts_query_only(self):
        payload = CopilotQuery(query="show critical alerts")

        self.assertEqual(payload.query, "show critical alerts")

    def test_copilot_rejects_extra_fields(self):
        with self.assertRaises(ValidationError):
            CopilotQuery(query="show critical alerts", message="show critical alerts")

    def test_log_payload_cannot_set_organization_id(self):
        payload = LogModel(
            source="firewall",
            event_type="SSH_ATTACK",
            severity="CRITICAL",
            message="attack detected",
            ip_address="10.0.0.1",
            organization_id="attacker-controlled-org",
        )

        self.assertEqual(payload.event_type, "ssh_attack")
        self.assertEqual(payload.severity, "critical")
        self.assertNotIn("organization_id", payload.model_dump())

    def test_collector_token_maps_to_configured_organization(self):
        original_settings = get_collector_organization_id.__globals__["settings"]
        get_collector_organization_id.__globals__["settings"] = SimpleNamespace(
            collector_api_keys={"collector-token": "org-123"}
        )
        try:
            self.assertEqual(
                get_collector_organization_id("collector-token"),
                "org-123",
            )
        finally:
            get_collector_organization_id.__globals__["settings"] = original_settings

    async def test_public_registration_can_be_disabled(self):
        original_settings = auth_service.settings
        original_audit = auth_service.write_audit_event
        auth_service.settings = SimpleNamespace(public_registration_enabled=False)
        async def noop_audit(**kwargs):
            return None

        auth_service.write_audit_event = noop_audit
        try:
            with self.assertRaises(HTTPException) as raised:
                await auth_service.register_user(
                    SimpleNamespace(
                        username="Analyst",
                        email="analyst@example.com",
                        password="long-enough-password",
                        organization_id="507f1f77bcf86cd799439011",
                    )
                )
        finally:
            auth_service.settings = original_settings
            auth_service.write_audit_event = original_audit

        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(raised.exception.detail, "Registration is disabled")


if __name__ == "__main__":
    unittest.main()
