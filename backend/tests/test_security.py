"""Security-hardening regression tests (Day 10).

Covered:

* request-body size limit (declared ``Content-Length`` and streamed bodies),
* optional in-memory rate limiting (429 + ``Retry-After``, health exempt),
* error handlers that never leak stack traces / paths / secrets,
* ``X-Content-Type-Options`` on responses,
* CORS defaults (local dev only) and preflight behavior,
* the documented URL-length contract.

No network access is performed anywhere in this module.
"""

from __future__ import annotations

import asyncio
import importlib
import sqlite3
from contextlib import contextmanager

from fastapi.testclient import TestClient


@contextmanager
def _client(tmp_path, monkeypatch, *, raise_server_exceptions=True, **env):
    """Fresh app + temporary database + patched environment for each test.

    ``app.main`` is reloaded because it reads settings at import time (see the
    existing ``client`` fixture in ``test_api.py`` for the same pattern).
    """
    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(tmp_path / "test.db"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    from app import config

    config.get_settings.cache_clear()

    import app.database as database
    import app.main as main

    importlib.reload(database)
    importlib.reload(main)

    with TestClient(main.app, raise_server_exceptions=raise_server_exceptions) as client:
        yield client


# --- request body size -----------------------------------------------------


def test_normal_analysis_still_works(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        response = client.post("/api/analyze", json={"url": "https://www.example.com/"})
    assert response.status_code == 200
    assert response.json()["risk_label"] == "Low"


def test_oversized_body_is_rejected_with_413(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        # ~20 KiB body: over the 16 KiB default and over the URL cap, which
        # shows the body limit fires before schema validation.
        response = client.post(
            "/api/analyze",
            json={"url": "https://example.com/" + "a" * (20 * 1024)},
        )
    assert response.status_code == 413
    assert "too large" in response.json()["detail"]


def test_oversized_body_error_carries_cors_headers(tmp_path, monkeypatch):
    """CORS is outermost so browsers can read 413/429 error bodies."""
    with _client(tmp_path, monkeypatch) as client:
        response = client.post(
            "/api/analyze",
            json={"url": "x" * (20 * 1024)},
            headers={"Origin": "http://localhost:5173"},
        )
    assert response.status_code == 413
    assert (
        response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    )


def test_body_limit_counts_streamed_bytes_without_content_length():
    """A body sent without Content-Length is still capped mid-stream."""
    from app.security import BodySizeLimitMiddleware

    async def downstream_app(scope, receive, send):
        while True:
            message = await receive()  # raises once the limit is exceeded
            if message["type"] != "http.request" or not message.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"x" * 64, "more_body": False}

    async def send(message):
        sent.append(message)

    middleware = BodySizeLimitMiddleware(downstream_app, max_bytes=32)
    scope = {"type": "http", "method": "POST", "path": "/api/analyze", "headers": []}
    asyncio.run(middleware(scope, receive, send))

    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


def test_url_length_contract_is_422(tmp_path, monkeypatch):
    """The documented URL cap (2048 characters) is enforced by validation."""
    with _client(tmp_path, monkeypatch) as client:
        response = client.post(
            "/api/analyze", json={"url": "https://example.com/" + "a" * 2048}
        )
    assert response.status_code == 422


# --- rate limiting ---------------------------------------------------------


def test_rate_limit_disabled_by_default(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        for _ in range(5):
            assert client.get("/api/history").status_code == 200


def test_rate_limit_returns_429_when_enabled(tmp_path, monkeypatch):
    with _client(
        tmp_path,
        monkeypatch,
        PHISHGUARD_RATE_LIMIT_ENABLED="true",
        PHISHGUARD_RATE_LIMIT_REQUESTS="3",
        PHISHGUARD_RATE_LIMIT_WINDOW_SECONDS="60",
    ) as client:
        statuses = [client.get("/api/history").status_code for _ in range(3)]
        assert statuses == [200, 200, 200]

        blocked = client.get("/api/history")
        assert blocked.status_code == 429
        assert blocked.headers.get("retry-after")
        assert "rate limit" in blocked.json()["detail"].lower()

        # Health probes stay available when the limiter is tripped.
        assert client.get("/api/health").status_code == 200


def test_rate_limiter_scope_covers_non_api_paths(tmp_path, monkeypatch):
    """D13-5: the limiter counts *every* path, not only ``/api/*``.

    The class docstring used to claim ``/api/*``; the observed behaviour (and
    now the docstring) is "any HTTP request except OPTIONS and the exempt
    health path". A request to ``/docs`` spends the same budget as an API call.
    """
    with _client(
        tmp_path,
        monkeypatch,
        PHISHGUARD_RATE_LIMIT_ENABLED="true",
        PHISHGUARD_RATE_LIMIT_REQUESTS="1",
    ) as client:
        # Development mode serves /docs; it consumes the only slot.
        assert client.get("/docs").status_code == 200
        assert client.get("/api/history").status_code == 429


def test_rate_limiter_exempts_preflights_and_health_without_spending_budget(
    tmp_path, monkeypatch
):
    """Only OPTIONS and the exempt paths bypass the counter (scope guard)."""
    with _client(
        tmp_path,
        monkeypatch,
        PHISHGUARD_RATE_LIMIT_ENABLED="true",
        PHISHGUARD_RATE_LIMIT_REQUESTS="1",
    ) as client:
        client.options("/api/analyze")  # CORS preflight: never counted
        assert client.get("/api/health").status_code == 200  # exempt: never counted
        # The single slot is still unused.
        assert client.get("/api/history").status_code == 200
        assert client.get("/api/history").status_code == 429


# --- error handling --------------------------------------------------------


def test_database_error_maps_to_503_without_internals(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, raise_server_exceptions=False) as client:
        import app.main as main

        def boom():
            raise sqlite3.OperationalError("no such table: scans (C:\\secret\\path)")

        monkeypatch.setattr(main, "count_scans", boom)
        response = client.get("/api/health")

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "secret" not in detail
    assert "table" not in detail
    assert "scan history" in detail.lower()


def test_unhandled_exception_returns_generic_500(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, raise_server_exceptions=False) as client:
        import app.main as main

        def boom():
            raise RuntimeError("boom secret-token-123")

        monkeypatch.setattr(main, "count_scans", boom)
        response = client.get("/api/health")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error."}
    assert "secret-token" not in response.text


# --- request limits ---------------------------------------------------------

def test_configured_history_limit_is_enforced(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, PHISHGUARD_HISTORY_LIMIT="1") as client:
        for url in ("https://a.example/", "https://b.example/"):
            assert client.post("/api/analyze", json={"url": url}).status_code == 200

        assert client.get("/api/history?limit=1").status_code == 200
        assert client.get("/api/history?limit=5").status_code == 422


def test_history_limit_default_keeps_documented_cap(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        assert client.get("/api/history?limit=100").status_code == 200
        assert client.get("/api/history?limit=101").status_code == 422


def test_security_headers_are_present(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        response = client.get("/api/health")
    assert response.headers.get("x-content-type-options") == "nosniff"


def test_default_cors_origins_are_local_dev_only():
    from app.config import Settings

    origins = Settings(_env_file=None).cors_origin_list
    assert origins
    assert "*" not in origins


def test_cors_preflight_allows_configured_origin_and_denies_others(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        allowed = client.options(
            "/api/analyze",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
            },
        )
        denied = client.options(
            "/api/analyze",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )

    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers
