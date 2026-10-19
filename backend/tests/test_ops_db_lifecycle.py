"""Database lifecycle tooling tests (Day 12).

Everything here runs against **disposable** SQLite files in ``tmp_path``. The
developer's real ``backend/phisguard.db`` is never opened, backed up, restored
or planned against, and no test starts a server.

Covered:

* ``backup`` writes a consistent, integrity-checked snapshot (including from a
  live WAL database) plus a SHA-256 manifest;
* ``verify`` accepts good backups and rejects non-database files, missing
  tables, and post-backup tampering;
* ``restore`` writes only to an explicit target, refuses to overwrite without
  ``--force``, preserves the replaced file, and never touches the source;
* ``retention-plan`` reports without deleting, and the module contains no
  delete code path at all;
* the tool's schema expectation matches the application's real schema.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sqlite3
from pathlib import Path

import pytest

from app.database import _SCHEMA
from ops import db_lifecycle as dl

REPO_ROOT = Path(__file__).resolve().parents[2]

_INSERT = """
INSERT INTO scans
    (url, normalized_url, scheme, host, risk_score, risk_label,
     findings_json, created_at, threat_intel_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _insert_rows(connection: sqlite3.Connection, count: int, *, start: int = 1,
                 created_at: str = "2026-01-01T00:00:00+00:00") -> None:
    for index in range(start, start + count):
        connection.execute(
            _INSERT,
            (
                f"https://example.com/{index}",
                f"https://example.com/{index}",
                "https",
                "example.com",
                10,
                "Low",
                json.dumps([{"code": "x"}]),
                created_at,
                None,
            ),
        )


def _make_database(path: Path, rows: int = 3, *, created_at: str = "2026-01-01T00:00:00+00:00") -> Path:
    """Create a database with the application's real schema and ``rows`` rows."""
    connection = sqlite3.connect(path)
    try:
        connection.executescript(_SCHEMA)
        _insert_rows(connection, rows, created_at=created_at)
        connection.commit()
    finally:
        connection.close()
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture()
def database(tmp_path: Path) -> Path:
    return _make_database(tmp_path / "test-live.db", rows=3)


# --------------------------------------------------------------------------- #
# backup
# --------------------------------------------------------------------------- #
def test_backup_writes_a_verified_snapshot_and_manifest(database: Path):
    manifest = dl.backup_database(database, label="unit-test")

    backup = Path(manifest["backup_path"])
    assert backup.is_file()
    assert backup.parent == database.parent / "backups"
    assert manifest["row_count"] == 3
    assert manifest["integrity_check"] == "ok"
    assert manifest["label"] == "unit-test"
    assert manifest["source_database"] == str(database)
    assert manifest["method"].startswith("sqlite3 online backup API")

    # The checksum in the manifest describes the file that was written.
    assert manifest["backup_sha256"] == _sha256(backup)
    manifest_path = Path(manifest["manifest_path"])
    assert manifest_path.is_file()
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["backup_sha256"] == manifest["backup_sha256"]

    # And the snapshot is independently usable.
    verification = dl.verify_backup(backup)
    assert verification["ok"] is True
    assert verification["checksum_verified"] is True
    assert verification["row_count"] == 3


def test_backup_captures_committed_rows_from_a_live_wal_database(tmp_path: Path):
    """The online backup API must see committed rows still held in the WAL."""
    database = _make_database(tmp_path / "wal.db", rows=0)

    writer = sqlite3.connect(database)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        _insert_rows(writer, 4)
        writer.commit()
        # The rows live in the -wal file at this point, not in the main file.
        assert database.with_name(database.name + "-wal").is_file()

        manifest = dl.backup_database(database)
        assert manifest["row_count"] == 4
        assert dl.verify_backup(manifest["backup_path"], expected_rows=4)["ok"] is True
    finally:
        writer.close()


def test_backup_refuses_to_overwrite_without_force(database: Path):
    first = dl.backup_database(database, stamp="20260101T000000Z")
    with pytest.raises(dl.LifecycleError, match="already exists"):
        dl.backup_database(database, stamp="20260101T000000Z")

    replaced = dl.backup_database(database, stamp="20260101T000000Z", force=True)
    assert replaced["backup_path"] == first["backup_path"]


def test_backup_of_a_missing_database_is_refused(tmp_path: Path):
    with pytest.raises(dl.LifecycleError, match="not found"):
        dl.backup_database(tmp_path / "does-not-exist.db")


def test_backup_output_directory_can_be_overridden(tmp_path: Path, database: Path):
    manifest = dl.backup_database(database, output_dir=tmp_path / "elsewhere")
    assert Path(manifest["backup_path"]).parent == tmp_path / "elsewhere"


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def test_verify_rejects_a_non_database_file(tmp_path: Path):
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"definitely not sqlite" * 200)

    payload = dl.verify_backup(garbage)
    assert payload["ok"] is False
    failed = {item["check"] for item in payload["checks"] if not item["ok"]}
    assert "integrity_check" in failed


def test_verify_rejects_an_empty_file(tmp_path: Path):
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    assert dl.verify_backup(empty)["ok"] is False


def test_verify_rejects_a_missing_file(tmp_path: Path):
    payload = dl.verify_backup(tmp_path / "nope.db")
    assert payload["ok"] is False
    assert payload["checks"][0]["check"] == "file_exists"


def test_verify_rejects_a_database_without_the_scans_table(tmp_path: Path):
    other = tmp_path / "other.db"
    connection = sqlite3.connect(other)
    try:
        connection.execute("CREATE TABLE unrelated (id INTEGER)")
        connection.commit()
    finally:
        connection.close()

    payload = dl.verify_backup(other)
    assert payload["ok"] is False
    failed = {item["check"] for item in payload["checks"] if not item["ok"]}
    assert "scans_table_present" in failed


def test_verify_rejects_a_backup_with_a_missing_required_column(tmp_path: Path):
    partial = tmp_path / "partial.db"
    connection = sqlite3.connect(partial)
    try:
        connection.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, url TEXT NOT NULL)")
        connection.commit()
    finally:
        connection.close()

    payload = dl.verify_backup(partial)
    assert payload["ok"] is False
    failed = {item["check"] for item in payload["checks"] if not item["ok"]}
    assert "required_columns" in failed


def test_verify_detects_tampering_after_the_backup_was_taken(database: Path):
    manifest = dl.backup_database(database)
    backup = Path(manifest["backup_path"])

    # Change one byte after the manifest was written. Whether SQLite's own
    # integrity_check notices depends on where the byte lands; verification must
    # fail either way.
    tampered = bytearray(backup.read_bytes())
    tampered[-1] ^= 0xFF
    backup.write_bytes(bytes(tampered))
    assert _sha256(backup) != manifest["backup_sha256"]

    payload = dl.verify_backup(backup)
    assert payload["ok"] is False
    assert payload["manifest_present"] is True


def test_verify_detects_a_manifest_checksum_mismatch(database: Path):
    """The manifest is what catches content-only edits SQLite still accepts."""
    manifest = dl.backup_database(database)
    backup = Path(manifest["backup_path"])
    manifest_path = Path(manifest["manifest_path"])

    recorded = json.loads(manifest_path.read_text(encoding="utf-8"))
    recorded["backup_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(recorded), encoding="utf-8")

    payload = dl.verify_backup(backup)
    assert payload["ok"] is False
    assert payload["checksum_verified"] is True
    failed = {item["check"] for item in payload["checks"] if not item["ok"]}
    assert "manifest_checksum" in failed


def test_verify_without_a_manifest_skips_the_checksum_but_still_passes(database: Path):
    manifest = dl.backup_database(database)
    backup = Path(manifest["backup_path"])
    Path(manifest["manifest_path"]).unlink()

    payload = dl.verify_backup(backup)
    assert payload["ok"] is True
    assert payload["manifest_present"] is False
    assert payload["checksum_verified"] is False


def test_verify_min_and_expected_row_counts(database: Path):
    manifest = dl.backup_database(database)
    backup = manifest["backup_path"]

    assert dl.verify_backup(backup, min_rows=3)["ok"] is True
    assert dl.verify_backup(backup, min_rows=4)["ok"] is False
    assert dl.verify_backup(backup, expected_rows=3)["ok"] is True
    assert dl.verify_backup(backup, expected_rows=99)["ok"] is False


# --------------------------------------------------------------------------- #
# restore
# --------------------------------------------------------------------------- #
def test_restore_into_a_separate_target_leaves_the_source_untouched(database: Path):
    manifest = dl.backup_database(database)
    before = _sha256(database)

    target = database.parent / "restore-validation.db"
    result = dl.restore_database(manifest["backup_path"], target)

    assert result["restored"] is True
    assert result["row_count"] == 3
    assert result["verified_against_backup"] is True
    assert result["replaced_file"] is None
    assert _sha256(database) == before  # source is byte-identical

    # The restored copy is a valid database in its own right.
    info = dl.database_info(target)
    assert info["integrity_ok"] is True
    assert info["row_count"] == 3
    assert dl.verify_backup(target)["ok"] is True


def test_restore_refuses_to_overwrite_an_existing_target(database: Path):
    manifest = dl.backup_database(database)
    target = database.parent / "occupied.db"
    target.write_bytes(b"existing file")

    with pytest.raises(dl.LifecycleError, match="target exists"):
        dl.restore_database(manifest["backup_path"], target)
    assert target.read_bytes() == b"existing file"


def test_restore_force_preserves_the_previous_file(database: Path):
    manifest = dl.backup_database(database)
    target = database.parent / "occupied.db"
    target.write_bytes(b"existing file")

    result = dl.restore_database(manifest["backup_path"], target, force=True)

    replaced = Path(result["replaced_file"])
    assert replaced.is_file()
    assert replaced.read_bytes() == b"existing file"      # nothing was destroyed
    assert dl.database_info(target)["row_count"] == 3


def test_restore_refuses_an_invalid_backup_and_creates_nothing(tmp_path: Path):
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"not a database" * 50)
    target = tmp_path / "target.db"

    with pytest.raises(dl.LifecycleError, match="failed verification"):
        dl.restore_database(garbage, target)
    assert not target.exists()


def test_restore_refuses_when_target_is_the_backup(database: Path):
    manifest = dl.backup_database(database)
    with pytest.raises(dl.LifecycleError, match="same file"):
        dl.restore_database(manifest["backup_path"], manifest["backup_path"])


def test_restore_of_a_missing_backup_is_refused(tmp_path: Path):
    with pytest.raises(dl.LifecycleError, match="not found"):
        dl.restore_database(tmp_path / "missing.db", tmp_path / "target.db")


# --------------------------------------------------------------------------- #
# retention-plan (report only)
# --------------------------------------------------------------------------- #
def test_retention_plan_reports_without_deleting(database: Path):
    before = dl.database_info(database)

    plan = dl.retention_plan(database, keep=1)

    assert plan["total_rows"] == 3
    assert plan["would_remove"] == 2
    assert plan["would_keep"] == 1
    assert plan["sample_removed_ids"] == [1, 2]
    assert plan["deletion_implemented"] is False
    assert "no delete code path" in plan["note"]

    after = dl.database_info(database)
    assert after["row_count"] == before["row_count"] == 3


def test_retention_plan_keep_zero_selects_everything(database: Path):
    plan = dl.retention_plan(database, keep=0)
    assert plan["would_remove"] == 3
    assert plan["would_keep"] == 0


def test_retention_plan_keep_larger_than_the_table_selects_nothing(database: Path):
    plan = dl.retention_plan(database, keep=99)
    assert plan["would_remove"] == 0
    assert plan["sample_removed_ids"] == []


def test_retention_plan_by_age(tmp_path: Path):
    database = tmp_path / "aged.db"
    connection = sqlite3.connect(database)
    try:
        connection.executescript(_SCHEMA)
        _insert_rows(connection, 2, start=1, created_at="2000-01-01T00:00:00+00:00")
        _insert_rows(connection, 3, start=3, created_at="2999-01-01T00:00:00+00:00")
        connection.commit()
    finally:
        connection.close()

    plan = dl.retention_plan(database, older_than_days=30)
    assert plan["total_rows"] == 5
    assert plan["would_remove"] == 2
    assert plan["sample_removed_ids"] == [1, 2]


def test_retention_plan_combined_policy_is_an_intersection(tmp_path: Path):
    database = tmp_path / "combined.db"
    connection = sqlite3.connect(database)
    try:
        connection.executescript(_SCHEMA)
        # Interleave the ages so neither policy contains the other:
        # ids 1/3/5 are ancient, ids 2/4/6 are far in the future.
        for index in range(1, 7):
            _insert_rows(
                connection,
                1,
                start=index,
                created_at=(
                    "2000-01-01T00:00:00+00:00" if index % 2 else "2999-01-01T00:00:00+00:00"
                ),
            )
        connection.commit()
    finally:
        connection.close()

    alone_keep = dl.retention_plan(database, keep=3)
    alone_age = dl.retention_plan(database, older_than_days=30)
    combined = dl.retention_plan(database, keep=3, older_than_days=30)

    assert alone_keep["sample_removed_ids"] == [1, 2, 3]
    assert alone_age["sample_removed_ids"] == [1, 3, 5]
    assert combined["total_rows"] == 6
    assert combined["would_remove"] == 2
    assert combined["would_keep"] == 4
    assert combined["sample_removed_ids"] == [1, 3]


def test_retention_plan_requires_a_policy_input(database: Path):
    with pytest.raises(dl.LifecycleError, match="keep and/or --older-than-days"):
        dl.retention_plan(database)


@pytest.mark.parametrize("kwargs", [{"keep": -1}, {"older_than_days": -1}])
def test_retention_plan_rejects_negative_values(database: Path, kwargs):
    with pytest.raises(dl.LifecycleError, match=">= 0"):
        dl.retention_plan(database, **kwargs)


def test_retention_plan_of_a_missing_database_is_refused(tmp_path: Path):
    with pytest.raises(dl.LifecycleError, match="not found"):
        dl.retention_plan(tmp_path / "missing.db", keep=1)


def test_module_contains_no_delete_code_path():
    """Guard the documented promise: the tool cannot delete scan history."""
    source = Path(dl.__file__).read_text(encoding="utf-8").upper()
    for statement in ("DELETE FROM", "DROP TABLE", "DROP INDEX", "TRUNCATE", "VACUUM"):
        assert statement not in source


# --------------------------------------------------------------------------- #
# info / schema / defaults
# --------------------------------------------------------------------------- #
def test_database_info_describes_the_file(database: Path):
    info = dl.database_info(database)
    assert info["exists"] is True
    assert info["row_count"] == 3
    assert info["integrity_ok"] is True
    assert info["integrity_check"] == "ok"
    assert info["missing_required_columns"] == []
    assert info["size_bytes"] > 0


def test_database_info_does_not_create_a_missing_database(tmp_path: Path):
    missing = tmp_path / "not-created.db"
    info = dl.database_info(missing)
    assert info["exists"] is False
    assert info["integrity_ok"] is False
    assert not missing.exists()


def test_database_info_tolerates_a_non_database_file(tmp_path: Path):
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"garbage" * 100)
    info = dl.database_info(garbage)
    assert info["exists"] is True
    assert info["integrity_ok"] is False


def test_tool_schema_expectation_matches_the_application_schema(tmp_path: Path):
    """The tool's schema constant must not drift from app/database.py."""
    database = _make_database(tmp_path / "schema.db", rows=0)
    connection = sqlite3.connect(database)
    try:
        actual = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
    finally:
        connection.close()

    assert set(dl.EXPECTED_COLUMNS) == actual
    assert set(dl.REQUIRED_COLUMNS) <= actual
    assert set(dl.OPTIONAL_COLUMNS) <= actual


def test_default_database_path_follows_application_configuration(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PHISHGUARD_DATABASE_PATH", str(tmp_path / "configured.db"))
    from app import config

    config.get_settings.cache_clear()
    try:
        assert dl.default_database_path() == config.get_settings().resolved_database_path
        assert dl.default_database_path() == tmp_path / "configured.db"
    finally:
        config.get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_backup_verify_and_plan(database: Path, tmp_path: Path, capsys):
    out_dir = tmp_path / "cli-backups"

    assert dl.main(["--database", str(database), "backup", "--output-dir", str(out_dir),
                    "--stamp", "20260101T000000Z"]) == 0
    printed = json.loads(capsys.readouterr().out)
    backup = Path(printed["backup_path"])
    assert backup.is_file()

    assert dl.main(["verify", "--backup", str(backup)]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    assert dl.main(["--database", str(database), "retention-plan", "--keep", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["deletion_implemented"] is False

    assert dl.main(["--database", str(database), "info"]) == 0
    assert json.loads(capsys.readouterr().out)["exists"] is True


def test_cli_accepts_database_before_or_after_the_subcommand(database: Path, capsys):
    assert dl.main(["--database", str(database), "info"]) == 0
    before = json.loads(capsys.readouterr().out)["database"]

    assert dl.main(["info", "--database", str(database)]) == 0
    after = json.loads(capsys.readouterr().out)["database"]

    assert before == after == str(database)


def test_cli_returns_failure_exit_codes(tmp_path: Path, database: Path, capsys):
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"garbage" * 100)
    assert dl.main(["verify", "--backup", str(garbage)]) == 1

    # A refused operation is an error, not a crash.
    assert dl.main(["--database", str(database), "retention-plan"]) == 1
    assert "error:" in capsys.readouterr().err

    assert dl.main(["--database", str(tmp_path / "missing.db"), "info"]) == 0


def test_cli_restore_round_trip(tmp_path: Path, database: Path, capsys):
    out_dir = tmp_path / "cli-restore-backups"
    assert dl.main(["--database", str(database), "backup", "--output-dir", str(out_dir),
                    "--stamp", "20260101T000000Z"]) == 0
    backup = Path(json.loads(capsys.readouterr().out)["backup_path"])

    target = tmp_path / "restored.db"
    assert dl.main(["restore", "--backup", str(backup), "--target", str(target)]) == 0
    assert json.loads(capsys.readouterr().out)["restored"] is True
    assert dl.database_info(target)["row_count"] == 3


def test_repository_gitignores_local_backups():
    ignored = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "backups/" in ignored
    assert "*.db-wal" in ignored


def test_ops_documentation_exists():
    readme = (REPO_ROOT / "backend" / "ops" / "README.md").read_text(encoding="utf-8")
    assert "retention" in readme.lower()
    assert "no delete code path" in readme.lower()
    assert "sqlite" in readme.lower()


def test_module_is_importable_without_reloading_the_app():
    """Importing the tool must not touch application settings or the database."""
    module = importlib.reload(dl)
    assert hasattr(module, "backup_database")
