"""Configuration and deployment-readiness tests (Day 11).

Covered:

* safe development defaults (local CORS, rate limiting off, docs on),
* ``.env`` is read from ``backend/.env`` regardless of the working directory,
* production mode disables the interactive docs by default,
* production mode fails fast on a wildcard CORS origin,
* the VirusTotal key never appears in ``repr()`` or the startup summary,
* log-level / history-limit validation,
* the endpoints behave as configured (/docs, /openapi.json, ?limit=).

No network access is performed anywhere in this module.
"""

from __future__ import annotations

import importlib
import logging
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import config as config_module
from app.config import Settings


def _settings(**env: str) -> Settings:
    """Build Settings from env vars only, ignoring any local backend/.env."""
    import os

    saved = {key: os.environ.get(key) for key in env}
    try:
        os.environ.update(env)
        return Settings(_env_file=None)
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(autouse=True)
def _hermetic_environment(monkeypatch):
    """Ignore ambient PHISHGUARD_*/VIRUSTOTAL_* variables from the host shell.

    ``tests/conftest.py`` applies the same guard to the whole suite; this module
    keeps its own copy so the configuration tests stay correct if they are run
    on their own.
    """
    import os

    for key in list(os.environ):
        if key.startswith("PHISHGUARD_") or key == "VIRUSTOTAL_API_KEY":
            monkeypatch.delenv(key, raising=False)


# --- safe defaults --------------------------------------------------------- #


def test_development_defaults_are_local_only():
    settings = Settings(_env_file=None)

    assert settings.environment == "development"
    assert settings.api_docs_enabled is True
    assert settings.cors_origin_list == [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    assert "*" not in settings.cors_origin_list
    assert settings.rate_limit_enabled is False
    assert settings.max_request_body_bytes == 16 * 1024
    assert settings.history_limit == 100
    assert settings.virustotal_configured is False


def test_no_development_warnings_outside_production():
    assert Settings(_env_file=None).deployment_warnings() == []


# --- .env anchoring -------------------------------------------------------- #


def test_env_file_is_anchored_to_the_backend_directory():
    env_file = Path(str(Settings.model_config["env_file"]))

    assert env_file.is_absolute()
    assert env_file == Path(config_module.__file__).resolve().parent.parent / ".env"
    assert env_file.name == ".env"


def test_env_file_is_not_read_from_the_working_directory(tmp_path, monkeypatch):
    """A .env in the process CWD must not be picked up (regression guard)."""
    monkeypatch.delenv("PHISHGUARD_DATABASE_PATH", raising=False)
    (tmp_path / ".env").write_text(
        "PHISHGUARD_DATABASE_PATH=marker-from-working-directory.db\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert Settings().database_path != "marker-from-working-directory.db"


def test_relative_database_path_resolves_under_backend(monkeypatch):
    monkeypatch.delenv("PHISHGUARD_DATABASE_PATH", raising=False)
    monkeypatch.chdir(Path(config_module.__file__).resolve().parent)  # app/

    resolved = Settings(_env_file=None).resolved_database_path

    assert resolved.is_absolute()
    assert resolved == Path(config_module.__file__).resolve().parent.parent / "phisguard.db"


def test_absolute_database_path_is_respected():
    absolute = Path.cwd() / "custom" / "store.db"
    settings = _settings(PHISHGUARD_DATABASE_PATH=str(absolute))

    assert settings.resolved_database_path == absolute


# --- production mode ------------------------------------------------------- #


def test_production_disables_api_docs_by_default():
    settings = _settings(PHISHGUARD_ENVIRONMENT="production")

    assert settings.api_docs_enabled is False
    assert settings.docs_enabled is None  # "automatic"


def test_docs_can_be_explicitly_enabled_in_production():
    settings = _settings(
        PHISHGUARD_ENVIRONMENT="production",
        PHISHGUARD_DOCS_ENABLED="true",
    )

    assert settings.api_docs_enabled is True
    assert any("docs" in warning for warning in settings.deployment_warnings())


def test_production_rejects_wildcard_cors_origin():
    with pytest.raises(ValidationError) as excinfo:
        _settings(PHISHGUARD_ENVIRONMENT="production", PHISHGUARD_CORS_ORIGINS="*")

    assert "wildcard" in str(excinfo.value)


def test_production_rejects_wildcard_among_explicit_origins():
    with pytest.raises(ValidationError):
        _settings(
            PHISHGUARD_ENVIRONMENT="production",
            PHISHGUARD_CORS_ORIGINS="https://app.example.com,*",
        )


def test_wildcard_cors_is_allowed_in_development():
    settings = _settings(PHISHGUARD_CORS_ORIGINS="*")

    assert settings.cors_origin_list == ["*"]


def test_production_warns_about_local_origins_and_disabled_limiter():
    settings = Settings(_env_file=None, environment="production")
    warnings = " ".join(settings.deployment_warnings())

    assert "rate limiting is disabled" in warnings
    assert "local development origin" in warnings


def test_production_with_explicit_origin_has_no_cors_warning():
    settings = _settings(
        PHISHGUARD_ENVIRONMENT="production",
        PHISHGUARD_CORS_ORIGINS="https://phisguard.example.com",
    )
    warnings = " ".join(settings.deployment_warnings())

    assert "local development origin" not in warnings
    assert "rate limiting is disabled" in warnings


# --- secret handling ------------------------------------------------------- #

_DUMMY_KEY = "dummy-key-must-never-be-logged"


def test_api_key_is_absent_from_repr_and_startup_summary(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", _DUMMY_KEY)
    settings = Settings(_env_file=None)

    assert settings.virustotal_configured is True
    assert _DUMMY_KEY not in repr(settings)
    summary = settings.startup_summary()
    assert _DUMMY_KEY not in repr(summary)
    assert summary["virustotal_key_configured"] is True


def test_startup_summary_reports_effective_database_path():
    absolute = Path.cwd() / "store.db"
    summary = _settings(PHISHGUARD_DATABASE_PATH=str(absolute)).startup_summary()

    assert summary["database_path"] == str(absolute)
    assert summary["environment"] == "development"
    assert summary["api_docs_enabled"] is True


# --- value validation ------------------------------------------------------ #


def test_log_level_is_normalised_and_validated():
    assert _settings(PHISHGUARD_LOG_LEVEL="WARN").log_level == "warning"
    assert _settings(PHISHGUARD_LOG_LEVEL="Debug").log_level == "debug"

    with pytest.raises(ValidationError):
        _settings(PHISHGUARD_LOG_LEVEL="verbose")


@pytest.mark.parametrize("value", ["0", "-1", "1001"])
def test_history_limit_bounds_are_enforced(value):
    with pytest.raises(ValidationError):
        _settings(PHISHGUARD_HISTORY_LIMIT=value)


def test_history_limit_accepts_configured_value():
    assert _settings(PHISHGUARD_HISTORY_LIMIT="250").history_limit == 250


def test_request_body_limit_bounds_are_enforced():
    with pytest.raises(ValidationError):
        _settings(PHISHGUARD_MAX_REQUEST_BODY_BYTES="10")


# --- applied behavior (fresh app per test) --------------------------------- #


@contextmanager
def _app_client(tmp_path, monkeypatch, **env):
    """Reload app.main with a temp database, ignoring any local .env file."""
    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(tmp_path / "test.db"))
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    # Force the settings away from any developer-provided backend/.env.
    monkeypatch.setitem(config_module.Settings.model_config, "env_file", None)
    config_module.get_settings.cache_clear()

    import app.main as main_module

    importlib.reload(main_module)
    with TestClient(main_module.app) as client:
        yield client

    config_module.get_settings.cache_clear()


def test_docs_are_served_in_development(tmp_path, monkeypatch):
    with _app_client(tmp_path, monkeypatch, PHISHGUARD_ENVIRONMENT="development") as client:
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200
        assert client.get("/api/health").status_code == 200


def test_docs_are_not_served_in_production(tmp_path, monkeypatch):
    with _app_client(tmp_path, monkeypatch, PHISHGUARD_ENVIRONMENT="production") as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/redoc").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        # The API itself keeps working.
        assert client.get("/api/health").status_code == 200
        response = client.post("/api/analyze", json={"url": "https://example.com/"})
        assert response.status_code == 200


def test_wildcard_cors_prevents_production_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("PHISHGUARD_ENVIRONMENT", "production")
    monkeypatch.setenv("PHISHGUARD_CORS_ORIGINS", "*")
    monkeypatch.setitem(config_module.Settings.model_config, "env_file", None)
    config_module.get_settings.cache_clear()

    import app.main as main_module

    with pytest.raises(ValidationError):
        importlib.reload(main_module)

    config_module.get_settings.cache_clear()


def test_configured_history_limit_is_enforced(tmp_path, monkeypatch):
    with _app_client(tmp_path, monkeypatch, PHISHGUARD_HISTORY_LIMIT="1") as client:
        for url in ("https://a.example/", "https://b.example/"):
            assert client.post("/api/analyze", json={"url": url}).status_code == 200

        assert client.get("/api/history?limit=1").status_code == 200
        assert client.get("/api/history?limit=5").status_code == 422


def test_history_limit_default_keeps_documented_cap(tmp_path, monkeypatch):
    with _app_client(tmp_path, monkeypatch) as client:
        assert client.get("/api/history?limit=100").status_code == 200
        assert client.get("/api/history?limit=101").status_code == 422


def test_configured_log_level_is_applied_on_startup(tmp_path, monkeypatch):
    logger = logging.getLogger("phishguard")
    original = logger.level
    try:
        with _app_client(tmp_path, monkeypatch, PHISHGUARD_LOG_LEVEL="warning"):
            assert logger.level == logging.WARNING
    finally:
        logger.setLevel(original)


# --- startup observability ------------------------------------------------- #


def test_startup_summary_is_emitted_and_never_contains_the_api_key(
    tmp_path, monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger="phishguard")

    with _app_client(tmp_path, monkeypatch, VIRUSTOTAL_API_KEY=_DUMMY_KEY):
        pass  # lifespan runs when the client starts

    assert "PhishGuard configuration:" in caplog.text
    assert "virustotal_key_configured': True" in caplog.text
    assert _DUMMY_KEY not in caplog.text


def test_production_startup_logs_deployment_warnings(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.WARNING, logger="phishguard")

    with _app_client(tmp_path, monkeypatch, PHISHGUARD_ENVIRONMENT="production"):
        pass

    assert "Deployment warning:" in caplog.text
    assert "rate limiting is disabled" in caplog.text


def test_production_startup_log_still_hides_the_api_key(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="phishguard")

    with _app_client(
        tmp_path, monkeypatch, PHISHGUARD_ENVIRONMENT="production", VIRUSTOTAL_API_KEY=_DUMMY_KEY
    ):
        pass

    assert _DUMMY_KEY not in caplog.text

