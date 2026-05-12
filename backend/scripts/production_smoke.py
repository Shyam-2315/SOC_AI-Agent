import json
import os
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv


load_dotenv(".env")


BASE_URL = os.getenv("SMOKE_BASE_URL", "http://127.0.0.1")
API_URL = os.getenv("SMOKE_API_URL", BASE_URL)
COLLECTOR_TOKEN = os.getenv("SMOKE_COLLECTOR_TOKEN", "test-collector-token")
DEMO_EMAIL = os.getenv("SMOKE_DEMO_EMAIL") or os.getenv(
    "DEMO_ADMIN_EMAIL",
    "demo.admin@aisoc.dev",
)
DEMO_PASSWORD = os.getenv("SMOKE_DEMO_PASSWORD") or os.getenv(
    "DEMO_ADMIN_PASSWORD",
    "DemoAdmin123!",
)


def _request(path: str, *, method: str = "GET", body=None, headers=None) -> tuple[int, str]:
    data = None
    final_headers = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        final_headers["Content-Type"] = "application/json"
    request = Request(f"{API_URL}{path}", data=data, method=method, headers=final_headers)
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8")
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")
    except URLError as exc:
        raise RuntimeError(f"request failed for {path}: {exc}") from exc


def _expect_ok(name: str, path: str) -> None:
    status, body = _request(path)
    if status >= 400:
        raise RuntimeError(f"{name} failed with {status}: {body}")
    print(f"ok: {name}")


def _docker_compose_ps() -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.prod.yml", "ps"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    print(result.stdout.strip())


def _optional_login() -> str | None:
    email = os.getenv("SMOKE_EMAIL")
    password = os.getenv("SMOKE_PASSWORD")
    if not email or not password:
        print("skip: authenticated API checks require SMOKE_EMAIL and SMOKE_PASSWORD")
        return None

    status, body = _request(
        "/auth/login",
        method="POST",
        body={"email": email, "password": password},
    )
    if status >= 400:
        raise RuntimeError(f"login failed with {status}: {body}")
    token = json.loads(body)["access_token"]
    print("ok: login")
    return token


def _optional_authenticated_checks(token: str | None) -> None:
    if not token:
        return
    for path in ("/alerts/", "/incidents/", "/soar/actions", "/threat-hunting/statistics"):
        status, body = _request(path, headers={"Authorization": f"Bearer {token}"})
        if status >= 400:
            raise RuntimeError(f"{path} failed with {status}: {body}")
        print(f"ok: {path}")


def _demo_smoke() -> None:
    if os.getenv("SMOKE_SKIP_DEMO", "").lower() in {"1", "true", "yes"}:
        print("skip: demo smoke disabled by SMOKE_SKIP_DEMO")
        return

    status, body = _request(
        "/auth/login",
        method="POST",
        body={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
    )
    if status >= 400:
        raise RuntimeError(
            "demo login failed. Run `python scripts/seed_demo.py` before smoke "
            f"validation. Status {status}: {body}"
        )
    token = json.loads(body)["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("ok: demo login")

    status, body = _request("/organizations/me", headers=headers)
    if status >= 400:
        raise RuntimeError(f"demo organization lookup failed with {status}: {body}")
    organization = json.loads(body)
    if not organization.get("name"):
        raise RuntimeError("demo organization response did not include a name")
    print("ok: demo organization")

    status, body = _request("/alerts/", headers=headers)
    if status >= 400:
        raise RuntimeError(f"demo alerts lookup failed with {status}: {body}")
    if not json.loads(body).get("items"):
        raise RuntimeError("demo alerts are empty")
    print("ok: demo alerts")

    status, body = _request("/incidents/", headers=headers)
    if status >= 400:
        raise RuntimeError(f"demo incidents lookup failed with {status}: {body}")
    if not json.loads(body).get("items"):
        raise RuntimeError("demo incidents are empty")
    print("ok: demo incidents")


def _optional_rule_smoke(token: str | None) -> None:
    if not token:
        print("skip: rule smoke requires SMOKE_EMAIL and SMOKE_PASSWORD")
        return

    rule_name = f"Smoke SSH Rule {int(time.time())}"
    status, body = _request(
        "/rules/",
        method="POST",
        headers={"Authorization": f"Bearer {token}"},
        body={
            "name": rule_name,
            "description": "Smoke test detection rule",
            "severity": "high",
            "event_type": "ssh_attack",
            "conditions": [
                {"field": "message", "operator": "contains", "value": "smoke failed login"}
            ],
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 - Brute Force",
            "enabled": True,
        },
    )
    if status >= 400:
        raise RuntimeError(f"rule create failed with {status}: {body}")
    rule = json.loads(body)["rule"]
    print("ok: create rule")

    status, body = _request(
        "/ingest/",
        method="POST",
        headers={"X-Collector-Token": COLLECTOR_TOKEN},
        body={
            "source": "smoke-test",
            "event_type": "ssh_attack",
            "severity": "medium",
            "message": "smoke failed login from production check",
            "ip_address": "10.10.10.11",
        },
    )
    if status >= 400:
        raise RuntimeError(f"rule ingestion failed with {status}: {body}")
    print("ok: ingest matching rule log")

    status, body = _request("/alerts/", headers={"Authorization": f"Bearer {token}"})
    if status >= 400:
        raise RuntimeError(f"alerts verification failed with {status}: {body}")
    alerts = json.loads(body).get("items", [])
    if not any(alert.get("matched_rule_id") == rule["id"] for alert in alerts):
        raise RuntimeError("matched-rule alert was not found")
    print("ok: verify rule alert")


def _optional_collector_smoke(token: str | None) -> None:
    if not token:
        print("skip: collector smoke requires SMOKE_EMAIL and SMOKE_PASSWORD")
        return

    collector_name = f"Smoke Collector {int(time.time())}"
    status, body = _request(
        "/collectors",
        method="POST",
        headers={"Authorization": f"Bearer {token}"},
        body={"name": collector_name, "type": "linux"},
    )
    if status >= 400:
        raise RuntimeError(f"collector create failed with {status}: {body}")
    created = json.loads(body)
    collector_id = created["collector"]["id"]
    collector_token = created["api_key"]
    print("ok: create collector")

    status, body = _request(
        "/collector/ingest",
        method="POST",
        headers={"X-Collector-Token": collector_token},
        body={
            "logs": [
                {
                    "source": "smoke-collector",
                    "event_type": "collector_smoke",
                    "severity": "low",
                    "message": "Collector batch smoke test log",
                    "ip_address": "10.10.10.12",
                }
            ]
        },
    )
    if status >= 400:
        raise RuntimeError(f"collector batch ingestion failed with {status}: {body}")
    response = json.loads(body)
    if response.get("accepted") != 1 or response.get("rejected") != 0:
        raise RuntimeError(f"collector batch ingestion returned unexpected counts: {body}")
    print("ok: collector batch ingestion")

    status, body = _request(
        f"/collectors/{collector_id}",
        method="DELETE",
        headers={"Authorization": f"Bearer {token}"},
    )
    if status >= 400:
        raise RuntimeError(f"collector cleanup failed with {status}: {body}")
    print("ok: delete collector")


def _ingestion_check() -> None:
    status, body = _request(
        "/ingest/",
        method="POST",
        headers={"X-Collector-Token": COLLECTOR_TOKEN},
        body={
            "source": "smoke-test",
            "event_type": "connection_attempt",
            "severity": "low",
            "message": "Production smoke test log",
            "ip_address": "10.10.10.10",
        },
    )
    if status >= 400:
        raise RuntimeError(f"ingestion failed with {status}: {body}")
    print("ok: ingestion")


def main() -> int:
    _docker_compose_ps()
    _expect_ok("nginx/backend readiness", "/health/ready")
    _expect_ok("liveness", "/health/live")
    token = _optional_login()
    _optional_authenticated_checks(token)
    _ingestion_check()
    _optional_collector_smoke(token)
    _optional_rule_smoke(token)
    _demo_smoke()
    print("production smoke test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"smoke test failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
