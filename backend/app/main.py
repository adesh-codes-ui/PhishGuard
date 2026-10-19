"""PhishGuard FastAPI application.

Endpoints
---------
* GET  /api/health            - service health + version
* POST /api/analyze           - analyze a URL, store it, return the result
* GET  /api/history           - recent scans (newest first)
* GET  /api/history/{id}      - full detail for one scan

The service never fetches the submitted URL.

Hardening (Day 10): request-body size limit and optional in-memory rate
limiting live in :mod:`app.security`; unhandled errors and database failures are
mapped to generic responses so no internals reach the client.

Deployment readiness (Day 11): settings live in :mod:`app.config`, are validated
at load time, and a non-secret summary is logged once at startup. The
interactive API docs are disabled in production by default.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .analyzer import InvalidURLError, analyze_url, get_registrable_domain
from .config import get_settings
from .database import count_scans, get_scan, init_db, list_scans, save_scan
from .providers import virustotal
from .schemas import (
    AnalysisResponse,
    AnalyzeRequest,
    ErrorResponse,
    FindingModel,
    HistoryResponse,
    ScanDetail,
    ScanSummary,
    ThreatIntelModel,
)
from .security import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)

logger = logging.getLogger("phishguard")

DISCLAIMER = (
    "This result is based on static heuristics only and is not proof that a URL "
    "is safe or unsafe. PhishGuard never visits submitted links. Always verify a "
    "site's identity through official channels before entering any credentials."
)


def _threat_intel_for(url: str) -> virustotal.ThreatIntelResult:
    """Look up optional external threat intelligence for ``url``.

    Kept as a thin wrapper so tests can stub the external provider. Any failure
    is contained inside the provider; this never raises for the caller.
    """
    return virustotal.lookup_url(url)


_settings = get_settings()


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Initialize storage and log a non-secret configuration summary."""
    init_db()

    # Apply the configured level to PhishGuard's own logger. uvicorn's access
    # and error logs remain controlled by uvicorn's own --log-level flag.
    phishguard_logger = logging.getLogger("phishguard")
    phishguard_logger.setLevel(_settings.log_level.upper())
    # uvicorn attaches handlers only to its own loggers, leaving the root logger
    # without one; without this fallback, INFO records emitted by PhishGuard are
    # silently dropped by the logging module's last-resort handler (WARNING+).
    if not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s: %(name)s: %(message)s"))
        logging.getLogger().addHandler(handler)

    # One line, never containing secrets: lets an operator confirm which values
    # actually took effect (including whether backend/.env was found).
    logger.info("PhishGuard configuration: %s", _settings.startup_summary())
    for warning in _settings.deployment_warnings():
        logger.warning("Deployment warning: %s", warning)

    yield


app = FastAPI(
    title="PhishGuard API",
    version=__version__,
    description="Explainable phishing-URL risk analysis. Does not fetch submitted URLs.",
    lifespan=_lifespan,
    # Interactive docs are disabled in production by default (Settings.api_docs_enabled).
    docs_url="/docs" if _settings.api_docs_enabled else None,
    redoc_url="/redoc" if _settings.api_docs_enabled else None,
    openapi_url="/openapi.json" if _settings.api_docs_enabled else None,
)

# Middleware order matters: the LAST one added is the OUTERMOST. CORS is added
# last so browsers can read the 413/429 error bodies produced by the two
# hardening middlewares underneath it.
app.add_middleware(
    BodySizeLimitMiddleware,
    max_bytes=_settings.max_request_body_bytes,
)
app.add_middleware(
    RateLimitMiddleware,
    enabled=_settings.rate_limit_enabled,
    requests=_settings.rate_limit_requests,
    window_seconds=_settings.rate_limit_window_seconds,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(sqlite3.Error)
async def _database_error_handler(request: Request, exc: sqlite3.Error) -> JSONResponse:
    """Map storage failures to a generic 503 (details only in the server log)."""
    logger.exception("Database error handling %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=503,
        content={"detail": "Scan history is temporarily unavailable."},
    )


@app.exception_handler(Exception)
async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort handler: generic 500 body, diagnostics stay server-side.

    This prevents stack traces, exception types, file paths and configuration
    details from ever reaching a client.
    """
    logger.exception("Unhandled error handling %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


@app.get("/api/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "version": __version__,
        "scans_stored": count_scans(),
    }


@app.post(
    "/api/analyze",
    response_model=AnalysisResponse,
    responses={400: {"model": ErrorResponse}},
)
def analyze(payload: AnalyzeRequest) -> AnalysisResponse:
    """Analyze a URL and persist the result in scan history."""
    try:
        analysis = analyze_url(payload.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    findings = analysis.to_dict()["findings"]

    # Optional external enrichment. Wrapped defensively so a provider problem
    # can never prevent us from returning the heuristic result.
    try:
        intel = _threat_intel_for(analysis.normalized_url)
    except Exception:  # pragma: no cover - provider already contains failures
        intel = virustotal.ThreatIntelResult(
            status=virustotal.STATUS_ERROR,
            message="Threat-intelligence lookup failed unexpectedly.",
        )
    intel_dict = intel.to_dict()

    scan_id = save_scan(
        url=analysis.input_url,
        normalized_url=analysis.normalized_url,
        scheme=analysis.scheme,
        host=analysis.host,
        risk_score=analysis.risk_score,
        risk_label=analysis.risk_label,
        findings=findings,  # type: ignore[arg-type]
        threat_intel=intel_dict,
    )

    return AnalysisResponse(
        id=scan_id,
        input_url=analysis.input_url,
        normalized_url=analysis.normalized_url,
        scheme=analysis.scheme,
        host=analysis.host,
        registrable_domain=analysis.registrable_domain,
        risk_score=analysis.risk_score,
        risk_label=analysis.risk_label,  # type: ignore[arg-type]
        findings=[FindingModel(**f) for f in findings],  # type: ignore[arg-type]
        disclaimer=DISCLAIMER,
        created_at=datetime.now(timezone.utc),
        threat_intel=ThreatIntelModel(**intel_dict),
    )


@app.get("/api/history", response_model=HistoryResponse)
def history(limit: int = Query(50, ge=1, le=_settings.history_limit)) -> HistoryResponse:
    """Return recent scans, newest first.

    ``limit`` is capped by ``PHISHGUARD_HISTORY_LIMIT`` (default 100), so the
    documented ``?limit=1..100`` contract is unchanged by default.
    """
    rows = list_scans(limit=limit)
    items = [
        ScanSummary(
            id=row["id"],
            url=row["url"],
            normalized_url=row["normalized_url"],
            host=row["host"],
            risk_score=row["risk_score"],
            risk_label=row["risk_label"],
            created_at=row["created_at"],
        )
        for row in rows
    ]
    return HistoryResponse(total=count_scans(), items=items)


@app.get(
    "/api/history/{scan_id}",
    response_model=ScanDetail,
    responses={404: {"model": ErrorResponse}},
)
def history_detail(scan_id: int) -> ScanDetail:
    """Return full details for a single stored scan."""
    row = get_scan(scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    intel_raw = row.get("threat_intel")
    return ScanDetail(
        id=row["id"],
        url=row["url"],
        normalized_url=row["normalized_url"],
        host=row["host"],
        scheme=row["scheme"],
        registrable_domain=get_registrable_domain(row["host"]),
        risk_score=row["risk_score"],
        risk_label=row["risk_label"],
        findings=[FindingModel(**f) for f in row["findings"]],
        created_at=row["created_at"],
        threat_intel=ThreatIntelModel(**intel_raw) if intel_raw else None,
    )
