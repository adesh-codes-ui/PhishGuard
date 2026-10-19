"""Optional VirusTotal (API v3) threat-intelligence provider.

Design notes
------------
* This provider only **looks up an existing report** (``GET /urls/{id}``). It
  never submits a URL for scanning, so user URLs are not sent to VirusTotal for
  analysis on our behalf.
* The API key is passed in by the caller (read from ``VIRUSTOTAL_API_KEY`` in
  :mod:`app.config`). It is never logged or returned.
* All failure modes (missing key, no report, rate limit, timeout, invalid key,
  network/server errors) are mapped to a :class:`ThreatIntelResult` instead of
  raising, so analysis can never be broken by the external dependency.
* This provider produces a *verdict* only. It does **not** contribute to the
  heuristic risk score; the two are kept deliberately separate.

Classification rule (the only place threat intel is classified)
--------------------------------------------------------------
``_classify`` maps VirusTotal's ``last_analysis_stats`` to a verdict:

* ``malicious > 0``  -> ``"malicious"``
* else ``suspicious > 0`` -> ``"suspicious"``
* else -> ``"no_detections"`` (which is NOT "safe")

Any status other than ``"found"`` yields ``"unavailable"``.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from ..config import Settings, get_settings

PROVIDER_NAME = "virustotal"

# Provider status values.
STATUS_DISABLED = "disabled"
STATUS_FOUND = "found"
STATUS_NOT_FOUND = "not_found"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_TIMEOUT = "timeout"
STATUS_INVALID_KEY = "invalid_key"
STATUS_ERROR = "error"

# Threat-intelligence verdicts (never merged with the heuristic score).
VERDICT_UNAVAILABLE = "unavailable"
VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_NO_DETECTIONS = "no_detections"

_SAFETY_NOTE = "Absence of detections is not proof that the URL is safe."


@dataclass
class ThreatIntelResult:
    """Normalized, JSON-serializable threat-intelligence result."""

    provider: str = PROVIDER_NAME
    status: str = STATUS_DISABLED
    available: bool = False
    verdict: str = VERDICT_UNAVAILABLE
    message: str = ""
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    total_engines: int | None = None
    last_analysis_date: datetime | None = None
    permalink: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping (datetimes as ISO 8601 strings)."""
        return {
            "provider": self.provider,
            "status": self.status,
            "available": self.available,
            "verdict": self.verdict,
            "message": self.message,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "total_engines": self.total_engines,
            "last_analysis_date": (
                self.last_analysis_date.isoformat()
                if self.last_analysis_date is not None
                else None
            ),
            "permalink": self.permalink,
        }


def virus_total_url_id(url: str) -> str:
    """Return the VirusTotal v3 URL id: base64url(sha256(url)) without padding."""
    digest = hashlib.sha256(url.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _epoch_to_datetime(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _classify(malicious: int | None, suspicious: int | None) -> str:
    """Classify VirusTotal stats into a verdict (see module docstring)."""
    if malicious is not None and malicious > 0:
        return VERDICT_MALICIOUS
    if suspicious is not None and suspicious > 0:
        return VERDICT_SUSPICIOUS
    return VERDICT_NO_DETECTIONS


def _verdict_message(
    verdict: str, malicious: int | None, suspicious: int | None, total: int | None
) -> str:
    if verdict == VERDICT_MALICIOUS:
        engines = f"{malicious} of {total}" if total else f"{malicious}"
        return f"VirusTotal: {engines} engines flagged this URL as malicious."
    if verdict == VERDICT_SUSPICIOUS:
        engines = f"{suspicious} of {total}" if total else f"{suspicious}"
        return f"VirusTotal: {engines} engines flagged this URL as suspicious."
    return f"No engines flagged this URL in the latest report. {_SAFETY_NOTE}"


class VirusTotalProvider:
    """Looks up existing VirusTotal reports for a URL."""

    name = PROVIDER_NAME

    def __init__(
        self,
        *,
        api_key: str | None,
        base_url: str = "https://www.virustotal.com/api/v3",
        timeout: float = 10.0,
        enabled: bool = True,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_key = (api_key or "").strip()
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._enabled = enabled
        self._client = client

    @property
    def enabled(self) -> bool:
        """Lookups only run when enabled and an API key is present."""
        return bool(self._enabled and self._api_key)

    def lookup(self, url: str) -> ThreatIntelResult:
        """Look up an existing report for ``url``. Never submits for scanning."""
        if not self.enabled:
            return ThreatIntelResult(
                status=STATUS_DISABLED,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=(
                    "VirusTotal lookups are disabled (no VIRUSTOTAL_API_KEY "
                    "configured). PhishGuard is using offline heuristics only."
                ),
            )

        url_id = virus_total_url_id(url)
        permalink = f"https://www.virustotal.com/gui/url/{url_id}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        endpoint = f"{self._base_url}/urls/{url_id}"

        try:
            response = self._get(endpoint, headers)
        except httpx.TimeoutException:
            return ThreatIntelResult(
                status=STATUS_TIMEOUT,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=f"VirusTotal lookup timed out after {self._timeout:g}s.",
                permalink=permalink,
            )
        except httpx.HTTPError as exc:
            return ThreatIntelResult(
                status=STATUS_ERROR,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=f"Network error contacting VirusTotal ({type(exc).__name__}).",
                permalink=permalink,
            )
        except Exception as exc:  # pragma: no cover - defensive catch-all
            return ThreatIntelResult(
                status=STATUS_ERROR,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=f"Unexpected error contacting VirusTotal ({type(exc).__name__}).",
                permalink=permalink,
            )

        return self._interpret(response, url_id, permalink)

    def _get(self, endpoint: str, headers: dict[str, str]) -> httpx.Response:
        if self._client is not None:
            return self._client.get(endpoint, headers=headers, timeout=self._timeout)
        with httpx.Client(timeout=self._timeout) as client:
            return client.get(endpoint, headers=headers)

    def _interpret(
        self, response: httpx.Response, url_id: str, permalink: str
    ) -> ThreatIntelResult:
        code = response.status_code

        if code == 404:
            return ThreatIntelResult(
                status=STATUS_NOT_FOUND,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=(
                    "VirusTotal has no existing report for this URL. PhishGuard "
                    "does not submit URLs for scanning automatically."
                ),
                permalink=permalink,
            )

        if code in (401, 403):
            return ThreatIntelResult(
                status=STATUS_INVALID_KEY,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=(
                    "VirusTotal rejected the API key (invalid, expired, or "
                    "insufficient permissions)."
                ),
                permalink=permalink,
            )

        if code == 429:
            message = "VirusTotal rate limit reached. Try again later."
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                message += f" Retry after {retry_after}s."
            return ThreatIntelResult(
                status=STATUS_RATE_LIMITED,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=message,
                permalink=permalink,
            )

        if code >= 500:
            return ThreatIntelResult(
                status=STATUS_ERROR,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=f"VirusTotal returned a server error (HTTP {code}).",
                permalink=permalink,
            )

        if code != 200:
            return ThreatIntelResult(
                status=STATUS_ERROR,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message=f"Unexpected VirusTotal response (HTTP {code}).",
                permalink=permalink,
            )

        try:
            attributes = response.json()["data"]["attributes"]
            stats = attributes.get("last_analysis_stats") or {}
        except (ValueError, KeyError, TypeError):
            return ThreatIntelResult(
                status=STATUS_ERROR,
                available=False,
                verdict=VERDICT_UNAVAILABLE,
                message="VirusTotal returned an unexpected response body.",
                permalink=permalink,
            )

        malicious = _to_int(stats.get("malicious"))
        suspicious = _to_int(stats.get("suspicious"))
        harmless = _to_int(stats.get("harmless"))
        undetected = _to_int(stats.get("undetected"))
        counted = [v for v in (malicious, suspicious, harmless, undetected) if v is not None]
        total = sum(counted) if counted else None
        verdict = _classify(malicious, suspicious)

        return ThreatIntelResult(
            status=STATUS_FOUND,
            available=True,
            verdict=verdict,
            message=_verdict_message(verdict, malicious, suspicious, total),
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            total_engines=total,
            last_analysis_date=_epoch_to_datetime(attributes.get("last_analysis_date")),
            permalink=permalink,
        )


def lookup_url(
    url: str,
    *,
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> ThreatIntelResult:
    """Convenience entry point that builds a provider from settings.

    ``client`` is injectable so tests can supply a mocked transport and never
    touch the network.
    """
    settings = settings or get_settings()
    provider = VirusTotalProvider(
        api_key=settings.virustotal_api_key,
        base_url=settings.virustotal_base_url,
        timeout=settings.virustotal_timeout_seconds,
        enabled=settings.virustotal_enabled,
        client=client,
    )
    return provider.lookup(url)
