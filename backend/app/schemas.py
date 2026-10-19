"""Pydantic request/response models for the API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

RiskLabel = Literal["Low", "Medium", "High", "Critical"]


class AnalyzeRequest(BaseModel):
    """Body of POST /api/analyze."""

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="The URL to analyze. Never fetched by the server.",
        examples=["https://example.com/login"],
    )


class FindingModel(BaseModel):
    code: str
    title: str
    description: str
    points: int
    severity: str


class ThreatIntelModel(BaseModel):
    """External threat-intelligence result, kept separate from heuristics.

    This is *not* part of the PhishGuard risk score. ``verdict`` is derived
    solely from the provider's data (see ``app.providers.virustotal``).
    """

    provider: str
    status: str
    available: bool
    verdict: str
    message: str
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    total_engines: int | None = None
    last_analysis_date: datetime | None = None
    permalink: str | None = None


class AnalysisResponse(BaseModel):
    """Response for a completed analysis, including the stored history id."""

    id: int
    input_url: str
    normalized_url: str
    scheme: str
    host: str
    registrable_domain: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_label: RiskLabel
    findings: list[FindingModel]
    disclaimer: str
    created_at: datetime
    # Optional external enrichment; never merged into risk_score/risk_label.
    threat_intel: ThreatIntelModel


class ScanSummary(BaseModel):
    id: int
    url: str
    normalized_url: str
    host: str
    risk_score: int
    risk_label: RiskLabel
    created_at: datetime


class ScanDetail(ScanSummary):
    scheme: str
    registrable_domain: str
    findings: list[FindingModel]
    # Stored threat-intel snapshot, if one was recorded for this scan.
    threat_intel: ThreatIntelModel | None = None


class HistoryResponse(BaseModel):
    total: int
    items: list[ScanSummary]


class ErrorResponse(BaseModel):
    detail: str
