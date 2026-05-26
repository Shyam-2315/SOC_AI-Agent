import unittest
from datetime import datetime, timezone

from app.services.attack_graphs import build_attack_graph


class IncidentAttackGraphTests(unittest.TestCase):
    def test_dos_incident_graph_contains_source_ip_endpoint_alert_incident(self):
        graph = build_attack_graph(
            {
                "_id": "incident-1",
                "title": "DoS Activity From 127.0.0.1",
                "severity": "high",
                "security_detection_type": "dos_attack",
                "security_target_path": "/health/ready",
                "related_alerts": [
                    {
                        "_id": "alert-1",
                        "title": "Possible DoS Activity",
                        "event_type": "dos_attack",
                        "severity": "high",
                        "ip_address": "127.0.0.1",
                        "target_path": "/health/ready",
                        "timestamp": datetime.now(timezone.utc),
                    }
                ],
                "soar_actions": [
                    {
                        "_id": "soar-1",
                        "action_type": "block_ip",
                        "automated_actions": ["Block IP"],
                    }
                ],
            }
        )

        node_types = {node.type for node in graph.nodes}
        edge_types = {(edge.source, edge.target, edge.label) for edge in graph.edges}

        self.assertTrue({"source_ip", "endpoint", "alert", "incident"}.issubset(node_types))
        self.assertIn("soar_action", node_types)
        self.assertTrue(any(label == "attacked" for _, _, label in edge_types))
        self.assertTrue(any(label == "triggered" for _, _, label in edge_types))
        self.assertTrue(any(label == "correlated" for _, _, label in edge_types))
        self.assertTrue(any(label == "response" for _, _, label in edge_types))

    def test_brute_force_incident_graph_contains_source_ip_host_user_alert_incident(self):
        graph = build_attack_graph(
            {
                "_id": "incident-2",
                "title": "Brute Force Against linux-app-01",
                "severity": "high",
                "related_alerts": [
                    {
                        "_id": "alert-2",
                        "title": "Brute force login attempt",
                        "event_type": "linux_ssh_failed_login",
                        "severity": "high",
                        "ip_address": "203.0.113.10",
                        "hostname": "linux-app-01",
                        "username": "admin",
                        "mitre_tactic_id": "TA0006",
                        "mitre_tactic_name": "Credential Access",
                        "mitre_technique_id": "T1110",
                        "mitre_technique_name": "Brute Force",
                    }
                ],
                "timeline_events": [
                    {
                        "alert_id": "alert-2",
                        "event_type": "linux_ssh_failed_login",
                        "message": "Repeated SSH failure",
                        "severity": "high",
                        "ip_address": "203.0.113.10",
                        "host": "linux-app-01",
                    }
                ],
            }
        )

        node_types = {node.type for node in graph.nodes}
        labels = {edge.label for edge in graph.edges}

        self.assertTrue({"source_ip", "host", "user", "alert", "incident"}.issubset(node_types))
        self.assertIn("mitre_technique", node_types)
        self.assertIn("targeted", labels)
        self.assertIn("attempted", labels)
        self.assertIn("triggered", labels)
        self.assertIn("correlated", labels)


if __name__ == "__main__":
    unittest.main()
