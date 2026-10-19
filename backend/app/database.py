"""SQLite persistence for scan history.

Uses the Python standard library ``sqlite3`` module with **parameterized
queries only**. User input is never interpolated into SQL strings, which
protects against SQL injection.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import get_settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    url            TEXT    NOT NULL,
    normalized_url TEXT    NOT NULL,
    scheme         TEXT    NOT NULL,
    host           TEXT    NOT NULL,
    risk_score     INTEGER NOT NULL,
    risk_label     TEXT    NOT NULL,
    findings_json  TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    threat_intel_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
"""

# Additive migrations for databases created by an earlier version. Column and
# table names are internal constants (never user input), so this is safe.
_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("scans", "threat_intel_json", "TEXT"),
)


def _database_file() -> Path:
    """Resolve the SQLite file path from settings.

    Relative paths resolve against the backend/ directory (see
    ``Settings.resolved_database_path``), so the location is independent of the
    process working directory.
    """
    return get_settings().resolved_database_path


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row access by column name."""
    connection = sqlite3.connect(_database_file())
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    """Create tables if they do not exist yet, then apply additive migrations."""
    with get_connection() as connection:
        connection.executescript(_SCHEMA)
        for table, column, ddl in _MIGRATIONS:
            _ensure_column(connection, table, column, ddl)


def _ensure_column(
    connection: sqlite3.Connection, table: str, column: str, ddl: str
) -> None:
    """Add ``column`` to ``table`` if it is missing (idempotent migration).

    ``table``, ``column`` and ``ddl`` are internal constants, never user input.
    """
    existing = {
        row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in existing:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def save_scan(
    *,
    url: str,
    normalized_url: str,
    scheme: str,
    host: str,
    risk_score: int,
    risk_label: str,
    findings: list[dict[str, Any]],
    threat_intel: dict[str, Any] | None = None,
) -> int:
    """Insert a scan and return its new row id."""
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (url, normalized_url, scheme, host, risk_score, risk_label,
                 findings_json, created_at, threat_intel_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                normalized_url,
                scheme,
                host,
                risk_score,
                risk_label,
                json.dumps(findings),
                created_at,
                json.dumps(threat_intel) if threat_intel is not None else None,
            ),
        )
        return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["findings"] = json.loads(data.pop("findings_json"))
    raw_intel = data.pop("threat_intel_json", None)
    data["threat_intel"] = json.loads(raw_intel) if raw_intel else None
    return data


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    """Return the most recent scans, newest first."""
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, url, normalized_url, scheme, host, risk_score, risk_label,
                   findings_json, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def get_scan(scan_id: int) -> dict[str, Any] | None:
    """Return a single scan by id, or None if it does not exist."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, url, normalized_url, scheme, host, risk_score, risk_label,
                   findings_json, created_at, threat_intel_json
            FROM scans
            WHERE id = ?
            """,
            (int(scan_id),),
        ).fetchone()
    return _row_to_dict(row) if row is not None else None


def count_scans() -> int:
    """Return the total number of stored scans."""
    with get_connection() as connection:
        row = connection.execute("SELECT COUNT(*) AS total FROM scans").fetchone()
    return int(row["total"])
