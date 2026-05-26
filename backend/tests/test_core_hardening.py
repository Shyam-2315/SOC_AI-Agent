import unittest
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.core.exceptions import register_exception_handlers
from app.core.middleware import RequestContextMiddleware, RequestSizeLimitMiddleware
from app.core.rate_limit import _LAST_SEEN, _REQUESTS, check_rate_limit


class CoreHardeningTests(unittest.TestCase):
    def test_rate_limit_returns_structured_http_exception(self):
        _REQUESTS.clear()
        _LAST_SEEN.clear()

        check_rate_limit(key="auth:test", limit=1, window_seconds=60)

        with self.assertRaises(HTTPException) as raised:
            check_rate_limit(key="auth:test", limit=1, window_seconds=60)

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(raised.exception.detail["code"], "rate_limit_exceeded")
        self.assertEqual(raised.exception.headers["Retry-After"], "60")

    def test_exception_handlers_return_structured_payload(self):
        app = FastAPI()
        app.add_middleware(RequestContextMiddleware)
        register_exception_handlers(app)

        @app.get("/boom")
        async def boom():
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "traffic_blocked",
                    "message": "Request blocked due to suspicious traffic behavior",
                    "details": {"reason": "dos"},
                },
            )

        client = TestClient(app)
        response = client.get("/boom", headers={"X-Request-ID": "req-123"})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "traffic_blocked")
        self.assertEqual(response.json()["error"]["details"], {"reason": "dos"})
        self.assertEqual(response.json()["request_id"], "req-123")

    def test_request_size_limit_rejects_large_payloads(self):
        app = FastAPI()
        app.add_middleware(RequestContextMiddleware)
        app.add_middleware(
            RequestSizeLimitMiddleware,
            settings=SimpleNamespace(request_max_body_bytes=10),
        )
        register_exception_handlers(app)

        @app.post("/upload")
        async def upload():
            return {"ok": True}

        client = TestClient(app)
        response = client.post(
            "/upload",
            content="x" * 11,
            headers={"content-type": "text/plain", "X-Request-ID": "req-size"},
        )

        self.assertEqual(response.status_code, 413)
        payload = response.json()
        self.assertEqual(payload["error"]["code"], "request_too_large")
        self.assertEqual(payload["request_id"], "req-size")


if __name__ == "__main__":
    unittest.main()
