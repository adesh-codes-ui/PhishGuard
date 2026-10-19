"""Tests for the optional VirusTotal provider.

Every test uses ``httpx.MockTransport`` so no network access and no real API key
are required. A placeholder key ("test-key") stands in for the real one.
"""

from __future__ import annotations

import base64
import hashlib

import httpx
import pytest

from app.providers import virustotal
from app.providers.virustotal import (
    STATUS_DISABLED,
    STATUS_ERROR,
    STATUS_FOUND,
    STATUS_INVALID_KEY,
    STATUS_NOT_FOUND,
    STATUS_RATE_LIMITED,
    STATUS_TIMEOUT,
    VERDICT_MALICIOUS,
    VERDICT_NO_DETECTIONS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNAVAILABLE,
    VirusTotalProvider,
    virus_total_url_id,
)

BASE_URL = "https://www.virustotal.com/api/v3"
SAMPLE_URL = "https://example.com/login"


def make_provider(handler, *, api_key: str | None = "test-key", enabled: bool = True):
    """Build a provider whose HTTP client is backed by a mock transport."""
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return VirusTotalProvider(
        api_key=api_key,
        base_url=BASE_URL,
        timeout=2.0,
        enabled=enabled,
        client=client,
    )


def _ok_payload(*, malicious=0, suspicious=0, harmless=70, undetected=5, date=1700000000):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": harmless,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "timeout": 0,
                },
                "last_analysis_date": date,
            }
        }
    }


def test_url_id_matches_virustotal_sha256_base64url_definition():
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(SAMPLE_URL.encode("utf-8")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    assert virus_total_url_id(SAMPLE_URL) == expected
    assert "=" not in virus_total_url_id(SAMPLE_URL)


def test_successful_lookup_extracts_stats_and_uses_report_endpoint():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["apikey"] = request.headers.get("x-apikey", "")
        return httpx.Response(200, json=_ok_payload(malicious=3, suspicious=2))

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_FOUND
    assert result.available is True
    assert result.malicious == 3
    assert result.suspicious == 2
    assert result.harmless == 70
    assert result.undetected == 5
    assert result.total_engines == 80
    assert result.verdict == VERDICT_MALICIOUS
    assert result.last_analysis_date is not None
    assert result.last_analysis_date.year == 2023
    # Lookup, never a submission: the id is in the path and no POST is used.
    assert seen["url"] == f"{BASE_URL}/urls/{virus_total_url_id(SAMPLE_URL)}"
    assert seen["apikey"] == "test-key"
    assert result.permalink == f"https://www.virustotal.com/gui/url/{virus_total_url_id(SAMPLE_URL)}"


def test_no_existing_report_returns_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}})

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_NOT_FOUND
    assert result.available is False
    assert result.verdict == VERDICT_UNAVAILABLE
    assert result.malicious is None


def test_rate_limit_is_handled_gracefully():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "60"}, json={"error": {}})

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_RATE_LIMITED
    assert result.available is False
    assert "rate limit" in result.message.lower()
    assert "60" in result.message


def test_timeout_is_handled():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_TIMEOUT
    assert result.available is False
    assert "timed out" in result.message.lower()


def test_network_error_is_handled():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_ERROR
    assert result.available is False


def test_invalid_api_key_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"code": "AuthenticationRequiredError"}})

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_INVALID_KEY
    assert result.available is False


def test_forbidden_is_treated_as_invalid_key():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {}})

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_INVALID_KEY


def test_provider_server_error_is_handled():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_ERROR
    assert "500" in result.message


def test_unexpected_body_is_handled():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": True})

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.status == STATUS_ERROR


def test_missing_api_key_disables_lookup_without_network_call():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=_ok_payload())

    provider = make_provider(handler, api_key=None)

    assert provider.enabled is False
    result = provider.lookup(SAMPLE_URL)

    assert result.status == STATUS_DISABLED
    assert result.available is False
    assert result.verdict == VERDICT_UNAVAILABLE
    assert calls["count"] == 0


def test_disabled_flag_disables_lookup_without_network_call():
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, json=_ok_payload())

    result = make_provider(handler, api_key="test-key", enabled=False).lookup(SAMPLE_URL)

    assert result.status == STATUS_DISABLED
    assert calls["count"] == 0


def test_blank_api_key_is_treated_as_missing():
    provider = make_provider(lambda r: httpx.Response(200, json=_ok_payload()), api_key="   ")
    assert provider.enabled is False


def test_suspicious_only_yields_suspicious_verdict():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok_payload(malicious=0, suspicious=1))

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.verdict == VERDICT_SUSPICIOUS


def test_no_detections_never_reports_safe():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok_payload(malicious=0, suspicious=0))

    result = make_provider(handler).lookup(SAMPLE_URL)

    assert result.verdict == VERDICT_NO_DETECTIONS
    assert result.verdict != "safe"
    # "safe" only appears in the explicit caution, never as a claim.
    assert "not proof" in result.message.lower()
    assert "safe" in result.message.lower()


def test_to_dict_matches_response_model_keys():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_ok_payload(malicious=1))

    data = make_provider(handler).lookup(SAMPLE_URL).to_dict()

    assert set(data) == {
        "provider",
        "status",
        "available",
        "verdict",
        "message",
        "malicious",
        "suspicious",
        "harmless",
        "undetected",
        "total_engines",
        "last_analysis_date",
        "permalink",
    }
    assert isinstance(data["last_analysis_date"], str)


@pytest.mark.parametrize("missing", [None, "", "   "])
def test_lookup_url_without_key_returns_disabled(missing, monkeypatch):
    """The module-level entry point respects a missing key (offline mode)."""
    settings = virustotal.get_settings()
    monkeypatch.setattr(settings, "virustotal_api_key", missing, raising=False)
    result = virustotal.lookup_url(SAMPLE_URL, settings=settings)
    assert result.status == STATUS_DISABLED


def test_api_key_is_read_only_from_the_dedicated_env_var(monkeypatch):
    """VIRUSTOTAL_API_KEY is read without the PHISHGUARD_ prefix."""
    from app import config

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "abc123")
    monkeypatch.delenv("PHISHGUARD_VIRUSTOTAL_API_KEY", raising=False)
    config.get_settings.cache_clear()
    try:
        settings = config.Settings()
        assert settings.virustotal_api_key == "abc123"
        assert settings.virustotal_configured is True
    finally:
        config.get_settings.cache_clear()


def test_defaults_enable_lookups_when_key_absent(monkeypatch):
    from app import config

    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    settings = config.Settings(_env_file=None)
    assert settings.virustotal_enabled is True
    assert settings.virustotal_timeout_seconds == 10.0
    assert settings.virustotal_base_url == BASE_URL
    assert settings.virustotal_configured is False

