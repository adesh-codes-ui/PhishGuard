"""API-level tests using FastAPI's TestClient (backs onto httpx)."""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Fresh app + temporary SQLite database for every test."""
    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(tmp_path / "test.db"))

    # Reset caches so settings pick up the patched environment.
    from app import config

    config.get_settings.cache_clear()

    # Import after env is set, and reload modules that cached settings.
    import app.database as database
    import app.main as main

    importlib.reload(database)
    importlib.reload(main)

    with TestClient(main.app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["scans_stored"] == 0


def test_analyze_valid_url(client):
    response = client.post("/api/analyze", json={"url": "https://www.example.com/"})
    assert response.status_code == 200
    body = response.json()
    assert body["risk_label"] == "Low"
    assert body["id"] > 0
    assert "disclaimer" in body
    assert isinstance(body["findings"], list)


def test_analyze_malformed_url_returns_400(client):
    response = client.post("/api/analyze", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_analyze_unclosed_ipv6_returns_400_not_500(client):
    # Regression: malformed IPv6 used to raise a raw ValueError (HTTP 500).
    response = client.post("/api/analyze", json={"url": "http://[::1"})
    assert response.status_code == 400
    assert "detail" in response.json()


def test_analyze_empty_url_returns_422(client):
    # Empty string fails Pydantic min_length validation.
    response = client.post("/api/analyze", json={"url": ""})
    assert response.status_code == 422


def test_analyze_missing_field_returns_422(client):
    response = client.post("/api/analyze", json={})
    assert response.status_code == 422


def test_analyze_phishing_url_is_high_risk(client):
    response = client.post(
        "/api/analyze",
        json={"url": "http://paypal.com.secure-login.evil.net/verify-account"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["risk_label"] == "Critical"
    assert body["risk_score"] >= 50


def test_history_records_scans(client):
    client.post("/api/analyze", json={"url": "https://www.example.com/"})
    client.post("/api/analyze", json={"url": "http://192.168.0.1/login"})

    response = client.get("/api/history")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2
    # Newest first.
    assert body["items"][0]["url"] == "http://192.168.0.1/login"


def test_history_detail(client):
    created = client.post(
        "/api/analyze", json={"url": "https://paypal-secure.com/login"}
    ).json()

    response = client.get(f"/api/history/{created['id']}")
    assert response.status_code == 200
    detail = response.json()
    assert detail["id"] == created["id"]
    assert detail["registrable_domain"] == "paypal-secure.com"
    assert len(detail["findings"]) >= 1


def test_history_detail_not_found(client):
    response = client.get("/api/history/999999")
    assert response.status_code == 404


def test_history_limit_validation(client):
    response = client.get("/api/history?limit=0")
    assert response.status_code == 422
    response = client.get("/api/history?limit=101")
    assert response.status_code == 422


def test_findings_are_json_safe(client):
    # Ensures our stored/returned findings are plain JSON (no SQL-injection-style
    # payloads survive as executable content).
    payload = "https://example.com/'; DROP TABLE scans;--"
    response = client.post("/api/analyze", json={"url": payload})
    assert response.status_code == 200
    # Table still exists and health works.
    assert client.get("/api/health").json()["status"] == "ok"


# --- Optional VirusTotal threat-intelligence integration ------------------- #


def test_analyze_without_vt_key_reports_disabled_intel(client):
    """With no API key configured the app keeps working in offline mode."""
    body = client.post("/api/analyze", json={"url": "https://www.example.com/"}).json()

    intel = body["threat_intel"]
    assert intel["provider"] == "virustotal"
    assert intel["status"] == "disabled"
    assert intel["verdict"] == "unavailable"
    assert intel["available"] is False
    assert body["risk_label"] == "Low"


def test_threat_intel_is_reported_separately_from_heuristics(client, monkeypatch):
    """Threat intel never changes the heuristic score or label."""
    url = "http://paypal.com.secure-login.evil.net/verify-account"
    baseline = client.post("/api/analyze", json={"url": url}).json()

    import app.main as main
    from app.providers.virustotal import (
        STATUS_FOUND,
        VERDICT_MALICIOUS,
        ThreatIntelResult,
    )

    stub = ThreatIntelResult(
        status=STATUS_FOUND,
        available=True,
        verdict=VERDICT_MALICIOUS,
        message="3 of 69 engines flagged this URL as malicious.",
        malicious=3,
        suspicious=1,
        harmless=60,
        undetected=5,
        total_engines=69,
        permalink="https://www.virustotal.com/gui/url/abc",
    )
    monkeypatch.setattr(main, "_threat_intel_for", lambda _url: stub)

    enriched = client.post("/api/analyze", json={"url": url}).json()

    assert enriched["threat_intel"]["status"] == "found"
    assert enriched["threat_intel"]["malicious"] == 3
    assert enriched["threat_intel"]["suspicious"] == 1
    assert enriched["threat_intel"]["total_engines"] == 69
    # Heuristic result is identical to the run without threat intel.
    assert enriched["risk_score"] == baseline["risk_score"]
    assert enriched["risk_label"] == baseline["risk_label"]


def test_history_detail_includes_stored_threat_intel(client, monkeypatch):
    import app.main as main
    from app.providers.virustotal import (
        STATUS_NOT_FOUND,
        VERDICT_UNAVAILABLE,
        ThreatIntelResult,
    )

    stub = ThreatIntelResult(
        status=STATUS_NOT_FOUND,
        available=False,
        verdict=VERDICT_UNAVAILABLE,
        message="VirusTotal has no existing report for this URL.",
    )
    monkeypatch.setattr(main, "_threat_intel_for", lambda _url: stub)

    created = client.post("/api/analyze", json={"url": "https://www.example.com/"}).json()
    detail = client.get(f"/api/history/{created['id']}").json()

    assert created["threat_intel"]["status"] == "not_found"
    assert detail["threat_intel"]["status"] == "not_found"


def test_history_list_stays_lightweight(client):
    """The summary list omits threat intel; only the detail includes it."""
    client.post("/api/analyze", json={"url": "https://www.example.com/"})
    items = client.get("/api/history").json()["items"]
    assert items and "threat_intel" not in items[0]


def test_offline_mode_never_calls_network(client, monkeypatch):
    """With no key, the provider must not attempt any HTTP request."""
    import app.providers.virustotal as vt

    def _boom(*_args, **_kwargs):  # pragma: no cover - must not run
        raise AssertionError("network access attempted without an API key")

    monkeypatch.setattr(vt.httpx, "Client", _boom)
    body = client.post("/api/analyze", json={"url": "https://www.example.com/"}).json()
    assert body["threat_intel"]["status"] == "disabled"


# --- Analyzer hardening (Day 3) -------------------------------------------- #


def test_analyze_bare_host_with_embedded_url_in_query_is_accepted(client):
    # Regression: "example.com/redirect?url=https://x" used to be rejected with
    # an "unsupported scheme" error because the scheme scan looked at the whole
    # string.
    response = client.post(
        "/api/analyze", json={"url": "example.com/redirect?url=https://evil.com"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["host"] == "example.com"
    assert body["normalized_url"].startswith("http://example.com/")


def test_analyze_obfuscated_numeric_host_is_flagged(client):
    response = client.post("/api/analyze", json={"url": "http://2130706433/"})
    assert response.status_code == 200
    body = response.json()
    codes = {f["code"] for f in body["findings"]}
    assert "numeric_host" in codes
    assert body["risk_score"] >= 25


def test_analyze_unsupported_scheme_returns_400(client):
    response = client.post("/api/analyze", json={"url": "ftp://example.com/file"})
    assert response.status_code == 400
    assert "scheme" in response.json()["detail"].lower()


def test_analyze_rejects_numeric_opaque_schemes_and_keeps_working(client):
    # Regression (Day 15): "tel:12345" and "javascript:1" were accepted as
    # "http://tel:12345" / "http://javascript:1" because the bare host:port
    # fallback matched any digits after a colon.
    for url in ("tel:12345", "data:1234", "javascript:1"):
        response = client.post("/api/analyze", json={"url": url})
        assert response.status_code == 400, url
        assert "scheme" in response.json()["detail"].lower()

    # The unsupported inputs were not persisted, and the API still works.
    assert client.get("/api/health").json()["scans_stored"] == 0
    assert client.post(
        "/api/analyze", json={"url": "https://www.example.com/"}
    ).status_code == 200


