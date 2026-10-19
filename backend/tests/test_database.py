"""Persistence tests, including the additive migration for existing databases."""

from __future__ import annotations

import importlib
import sqlite3

import pytest


@pytest.fixture()
def database(tmp_path, monkeypatch):
    """Reload app.database against a fresh temporary file for each test."""
    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(tmp_path / "test.db"))

    from app import config

    config.get_settings.cache_clear()

    import app.database as database_module

    importlib.reload(database_module)
    yield database_module
    config.get_settings.cache_clear()


def _create_legacy_db(path) -> None:
    """Create a database using the pre-threat-intel schema."""
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            url            TEXT    NOT NULL,
            normalized_url TEXT    NOT NULL,
            scheme         TEXT    NOT NULL,
            host           TEXT    NOT NULL,
            risk_score     INTEGER NOT NULL,
            risk_label     TEXT    NOT NULL,
            findings_json  TEXT    NOT NULL,
            created_at     TEXT    NOT NULL
        );
        """
    )
    connection.execute(
        """
        INSERT INTO scans
            (url, normalized_url, scheme, host, risk_score, risk_label,
             findings_json, created_at)
        VALUES ('https://a.com/', 'https://a.com/', 'https', 'a.com', 0, 'Low',
                '[]', '2024-01-01T00:00:00+00:00')
        """
    )
    connection.commit()
    connection.close()


def test_init_db_migrates_legacy_schema(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    _create_legacy_db(db_path)

    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(db_path))
    from app import config

    config.get_settings.cache_clear()
    import app.database as database_module

    importlib.reload(database_module)

    # Migration is idempotent and must not lose existing rows.
    database_module.init_db()
    database_module.init_db()

    rows = database_module.list_scans()
    assert len(rows) == 1
    assert rows[0]["findings"] == []
    assert rows[0]["threat_intel"] is None

    # The migrated column is writable/readable for new scans.
    new_id = database_module.save_scan(
        url="https://b.com/",
        normalized_url="https://b.com/",
        scheme="https",
        host="b.com",
        risk_score=0,
        risk_label="Low",
        findings=[],
        threat_intel={"status": "disabled", "provider": "virustotal"},
    )
    detail = database_module.get_scan(new_id)
    assert detail is not None
    assert detail["threat_intel"] == {"status": "disabled", "provider": "virustotal"}

    config.get_settings.cache_clear()


def test_resolved_database_path_matches_configured_file(database, tmp_path):
    """Settings.resolved_database_path must point to the actual DB file."""
    from app import config

    settings = config.get_settings()
    assert settings.resolved_database_path == tmp_path / "test.db"


def test_save_scan_without_intel_stores_null(database):
    database.init_db()
    scan_id = database.save_scan(
        url="https://a.com/",
        normalized_url="https://a.com/",
        scheme="https",
        host="a.com",
        risk_score=0,
        risk_label="Low",
        findings=[{"code": "x"}],
    )
    detail = database.get_scan(scan_id)
    assert detail is not None
    assert detail["threat_intel"] is None
    assert detail["findings"] == [{"code": "x"}]



