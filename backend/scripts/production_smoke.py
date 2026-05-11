import json
import os
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = os.getenv("SMOKE_BASE_URL", "http://127.0.0.1")
API_URL = os.getenv("SMOKE_API_URL", BASE_URL)
COLLECTOR_TOKEN = os.getenv("SMOKE_COLLECTOR_TOKEN", "test-collector-token")


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
    print("production smoke test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"smoke test failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
