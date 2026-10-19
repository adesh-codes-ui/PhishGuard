"""Application configuration.

All settings come from environment variables and/or a local ``.env`` file.
Nothing secret is hardcoded here, and no secret value is ever included in
``repr()`` or in the startup summary the app logs (see ``startup_summary``).

The ``.env`` file is anchored to ``backend/.env`` regardless of the process
working directory. A relative ``env_file`` would instead be resolved against the
current directory, silently ignoring the operator's file (or picking up an
unrelated one) when the server is started from anywhere else.

Nothing here is a security boundary: an in-process rate limiter cannot be, and
secrets are only protected to the extent that the host, the ``.env`` file and
the process environment are protected.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# ``backend/`` — the parent of the ``app`` package. Used to anchor paths so they
# do not depend on the process working directory.
_BACKEND_DIR = Path(__file__).resolve().parent.parent

# Log levels accepted by ``logging``/uvicorn. Normalised to lower case.
_LOG_LEVELS = frozenset({"critical", "error", "warning", "info", "debug", "trace"})


class Settings(BaseSettings):
    """Runtime settings loaded from the environment."""

    model_config = SettingsConfigDict(
        env_prefix="PHISHGUARD_",
        env_file=_BACKEND_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # "development" keeps the local-first defaults below. "production" enables
    # fail-fast checks and, by default, disables the interactive API docs.
    environment: Literal["development", "production"] = "development"

    # Path to the SQLite database file. Relative paths resolve against backend/
    # (via ``resolved_database_path``), regardless of the working directory.
    database_path: str = "phisguard.db"

    # Origins allowed to call the API. Kept as a raw string so it is easy to set
    # in the environment, then parsed into a list.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    log_level: str = "info"

    # Maximum number of history rows returned in a single request. Also the
    # upper bound accepted by ``GET /api/history?limit=``.
    history_limit: int = Field(default=100, ge=1, le=1000)

    # Interactive API docs (/docs, /redoc, /openapi.json). ``None`` means
    # "automatic": enabled in development, disabled in production. Set to
    # ``true`` to expose them in production (e.g. on an internal-only host).
    docs_enabled: bool | None = None

    # --- API hardening (Day 10) -------------------------------------------- #
    # Largest accepted request body, in bytes. Enforced by middleware BEFORE
    # the body is parsed, so an oversized payload is rejected without being
    # read into memory.
    max_request_body_bytes: int = Field(default=16 * 1024, ge=1024, le=10 * 1024 * 1024)

    # Optional in-memory rate limiting. Disabled by default because the counter
    # lives in this process only: with ``uvicorn --workers N`` each worker has
    # its own budget. Treat it as best-effort abuse mitigation and put a shared
    # limiter (gateway/reverse proxy) in front for real protection.
    rate_limit_enabled: bool = False
    rate_limit_requests: int = Field(default=60, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)

    # --- Optional VirusTotal threat-intelligence integration --------------- #
    # The API key is read ONLY from the VIRUSTOTAL_API_KEY environment variable
    # (or a VIRUSTOTAL_API_KEY line in backend/.env). The explicit
    # validation_alias intentionally bypasses the "PHISHGUARD_" prefix above.
    # The key is never returned to the client, never committed (.env is
    # git-ignored), and ``repr=False`` keeps it out of ``repr(settings)`` and any
    # accidental logging of the settings object.
    virustotal_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("VIRUSTOTAL_API_KEY"),
        repr=False,
    )

    # Whether to attempt external lookups at all (independent of the key).
    virustotal_enabled: bool = True

    # Official VirusTotal API v3 base URL.
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"

    # Per-request timeout (seconds) for the external lookup.
    virustotal_timeout_seconds: float = Field(default=10.0, gt=0, le=300)

    # --- Validation -------------------------------------------------------- #

    @field_validator("log_level")
    @classmethod
    def _normalise_log_level(cls, value: str) -> str:
        """Accept any case, reject values uvicorn/``logging`` would not honour."""
        level = value.strip().lower()
        if level == "warn":
            level = "warning"
        if level not in _LOG_LEVELS:
            # The offending value is deliberately not echoed: a mis-set variable
            # could in principle contain something sensitive.
            raise ValueError(
                "PHISHGUARD_LOG_LEVEL must be one of "
                + ", ".join(sorted(_LOG_LEVELS))
            )
        return level

    @model_validator(mode="after")
    def _check_production_safety(self) -> "Settings":
        """Fail fast on settings that are unsafe once ``environment=production``.

        Only the origin list is inspected; no value here is a secret, so the
        error message is safe to surface. The app refuses to start rather than
        serving a production deployment that reflects any origin.
        """
        if self.environment == "production" and "*" in self.cors_origin_list:
            raise ValueError(
                "PHISHGUARD_CORS_ORIGINS must list explicit origins in production "
                "(a wildcard '*' is not allowed)."
            )
        return self

    # --- Derived values ---------------------------------------------------- #

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def resolved_database_path(self) -> Path:
        """Absolute database path; relative settings resolve against backend/."""
        path = Path(self.database_path)
        if not path.is_absolute():
            path = _BACKEND_DIR / path
        return path

    @property
    def api_docs_enabled(self) -> bool:
        """Whether /docs, /redoc and /openapi.json are served."""
        if self.docs_enabled is not None:
            return self.docs_enabled
        return self.environment != "production"

    @property
    def virustotal_configured(self) -> bool:
        """True when a non-empty API key is present."""
        return bool(self.virustotal_api_key and self.virustotal_api_key.strip())

    def startup_summary(self) -> dict[str, object]:
        """Non-secret configuration snapshot, safe to write to the log.

        Never contains the VirusTotal key (only whether one is configured).
        """
        return {
            "environment": self.environment,
            "database_path": str(self.resolved_database_path),
            "cors_origins": self.cors_origin_list,
            "log_level": self.log_level,
            "history_limit": self.history_limit,
            "api_docs_enabled": self.api_docs_enabled,
            "max_request_body_bytes": self.max_request_body_bytes,
            "rate_limit_enabled": self.rate_limit_enabled,
            "rate_limit_requests": self.rate_limit_requests,
            "rate_limit_window_seconds": self.rate_limit_window_seconds,
            "virustotal_enabled": self.virustotal_enabled,
            "virustotal_key_configured": self.virustotal_configured,
            "virustotal_timeout_seconds": self.virustotal_timeout_seconds,
        }

    def deployment_warnings(self) -> list[str]:
        """Non-fatal production concerns, each logged once at startup."""
        if self.environment != "production":
            return []

        warnings: list[str] = []
        if not self.rate_limit_enabled:
            warnings.append(
                "rate limiting is disabled; rely on a reverse proxy / gateway "
                "limit for production traffic (the in-process limiter is not one)."
            )
        if any(origin.startswith(("http://localhost", "http://127.0.0.1")) for origin in self.cors_origin_list):
            warnings.append(
                "PHISHGUARD_CORS_ORIGINS still lists a local development origin; "
                "set it to the deployed frontend origin."
            )
        if self.docs_enabled is True:
            warnings.append(
                "API docs are explicitly enabled in production; restrict access "
                "at the proxy if the service is internet-facing."
            )
        return warnings


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
