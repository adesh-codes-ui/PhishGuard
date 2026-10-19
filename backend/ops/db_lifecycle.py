#!/usr/bin/env python3
"""Database lifecycle tooling for PhishGuard: info, backup, verify, restore.

Day 12 (deployment artifacts and data lifecycle). Standard library only; no
new dependency, no network access of any kind.

Safety contract
---------------
* **Read-only by default.** ``info`` and ``verify`` never modify the database
  they inspect, and ``verify`` opens backup files with ``mode=ro`` so it cannot
  alter them even by accident.
* **No automatic deletion.** ``retention-plan`` *reports* what a policy would
  remove and contains **no delete code path at all**. Enabling retention is an
  unresolved product decision (see ``ops/README.md`` and
  ``eval/DAY12_REPORT.md``).
* **Restore writes only to an explicit ``--target``.** It refuses to overwrite
  an existing file unless ``--force`` is given, and even then moves the previous
  file aside (``<name>.replaced-<timestamp>``) instead of destroying it. It
  never touches the configured database path unless that path is named
  explicitly as the target.
* **Backups use SQLite's online backup API** (``sqlite3.Connection.backup``),
  which reads through SQLite's own locking protocol and therefore accounts for a
  live database's journal/WAL state. Copying the file with the OS while a writer
  is active can capture a torn or stale snapshot and is *not* used here.
* No URL is fetched, resolved or submitted; the tool only reads local files.

The schema expectation below is duplicated deliberately: verifying a backup must
not depend on the application being importable, and a test
(``tests/test_ops_db_lifecycle.py``) pins it to the real schema so the two
cannot drift apart unnoticed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

if __package__ in (None, ""):  # allow "python ops/db_lifecycle.py"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

BACKEND_DIR = Path(__file__).resolve().parents[1]

SCANS_TABLE = "scans"

# Columns required for the tool to read a backup as PhishGuard scan history.
REQUIRED_COLUMNS = (
    "id",
    "url",
    "normalized_url",
    "scheme",
    "host",
    "risk_score",
    "risk_label",
    "findings_json",
    "created_at",
)
# Added by the Day 8 additive migration; absent in pre-migration databases.
OPTIONAL_COLUMNS = ("threat_intel_json",)
EXPECTED_COLUMNS = REQUIRED_COLUMNS + OPTIONAL_COLUMNS

DEFAULT_BACKUP_DIRNAME = "backups"
MANIFEST_SUFFIX = ".json"
TOOL_NAME = "backend/ops/db_lifecycle.py"

_SHA_CHUNK = 1 << 20


class LifecycleError(RuntimeError):
    """A lifecycle operation was refused or could not be completed safely."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _utc_stamp(now: datetime | None = None) -> str:
    """Filesystem-safe UTC timestamp used in backup file names."""
    moment = now or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _as_path(value: Path | str) -> Path:
    return Path(value).expanduser()


def _manifest_path(backup_path: Path) -> Path:
    """``x.db`` -> ``x.db.json`` (a sidecar, never a second database file)."""
    return backup_path.with_name(backup_path.name + MANIFEST_SUFFIX)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_SHA_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _connect_readonly(path: Path) -> sqlite3.Connection:
    """Open ``path`` read-only so it can never be modified."""
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _table_present(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return row is not None


def _columns(connection: sqlite3.Connection, table: str = SCANS_TABLE) -> list[str]:
    return [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]


def _row_count(connection: sqlite3.Connection, table: str = SCANS_TABLE) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _integrity_check(connection: sqlite3.Connection) -> str:
    """Return SQLite's own ``PRAGMA integrity_check`` verdict."""
    try:
        return str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    except sqlite3.Error as exc:  # e.g. "file is not a database"
        return f"error: {exc}"


def default_database_path() -> Path:
    """The database path the application would actually use.

    Reads the app's own configuration so this tool and the server can never
    disagree about where the data lives (the Day 11 "two sources of truth" bug
    class). Falls back to ``backend/phisguard.db`` if the app cannot be imported.
    """
    try:
        from app.config import get_settings

        return Path(get_settings().resolved_database_path)
    except Exception:  # pragma: no cover - only when run outside the venv
        return BACKEND_DIR / "phisguard.db"


# --------------------------------------------------------------------------- #
# info
# --------------------------------------------------------------------------- #
def database_info(database: Path | str) -> dict[str, Any]:
    """Describe a database file without changing it.

    The connection is opened read/write (SQLite requires that for some pragmas),
    but no statement here writes; ``init_db()``/migrations are never called.
    """
    path = _as_path(database)
    info: dict[str, Any] = {
        "database": str(path),
        "exists": path.is_file(),
        "backup_directory": str(path.parent / DEFAULT_BACKUP_DIRNAME),
    }
    if not path.is_file():
        info["integrity_ok"] = False
        info["note"] = "database file does not exist yet (created on first server start)"
        return info

    info["size_bytes"] = path.stat().st_size
    # Sidecars that only exist while the database is in a journal/WAL state.
    info["wal_file_present"] = path.with_name(path.name + "-wal").is_file()
    info["shm_file_present"] = path.with_name(path.name + "-shm").is_file()
    info["journal_file_present"] = path.with_name(path.name + "-journal").is_file()
    info["integrity_check"] = "not run"
    info["integrity_ok"] = False

    connection = sqlite3.connect(path)
    try:
        connection.row_factory = sqlite3.Row
        try:
            info["journal_mode"] = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            info["user_version"] = int(connection.execute("PRAGMA user_version").fetchone()[0])
            info["page_size"] = int(connection.execute("PRAGMA page_size").fetchone()[0])
            present = _table_present(connection, SCANS_TABLE)
            info["scans_table_present"] = present
            info["columns"] = _columns(connection) if present else []
            info["missing_required_columns"] = [
                column for column in REQUIRED_COLUMNS if column not in info["columns"]
            ]
            if present:
                info["row_count"] = _row_count(connection)
                oldest, newest = connection.execute(
                    f"SELECT MIN(created_at), MAX(created_at) FROM {SCANS_TABLE}"
                ).fetchone()
                info["oldest_created_at"] = oldest
                info["newest_created_at"] = newest
            integrity = _integrity_check(connection)
            info["integrity_check"] = integrity
            info["integrity_ok"] = integrity == "ok"
        except sqlite3.Error as exc:
            # e.g. the file exists but is not a SQLite database.
            info["integrity_check"] = f"error: {exc}"
            info["note"] = "file exists but is not a readable SQLite database"
    finally:
        connection.close()
    return info


# --------------------------------------------------------------------------- #
# backup
# --------------------------------------------------------------------------- #
def backup_database(
    database: Path | str,
    *,
    output_dir: Path | str | None = None,
    force: bool = False,
    label: str | None = None,
    stamp: str | None = None,
) -> dict[str, Any]:
    """Write a consistent snapshot of ``database`` using SQLite's backup API.

    Returns the manifest that was written next to the backup. Raises
    :class:`LifecycleError` if the source is missing, the destination already
    exists (unless ``force``), or the snapshot fails ``integrity_check`` -- in
    which case the unusable file is removed rather than left behind.
    """
    source_path = _as_path(database)
    if not source_path.is_file():
        raise LifecycleError(f"database not found: {source_path}")

    out_dir = _as_path(output_dir) if output_dir else source_path.parent / DEFAULT_BACKUP_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = stamp or _utc_stamp()
    backup_path = out_dir / f"{source_path.stem}-backup-{stamp}.db"
    if backup_path.exists() and not force:
        raise LifecycleError(f"backup already exists (use --force to replace): {backup_path}")

    source = sqlite3.connect(source_path)
    target = sqlite3.connect(backup_path)
    try:
        target.row_factory = sqlite3.Row
        # Online backup API. It reads through SQLite's normal locking protocol,
        # so committed rows in a live WAL/journal database are included and the
        # snapshot is internally consistent.
        source.backup(target)
        target.commit()
        integrity = _integrity_check(target)
        rows = _row_count(target) if _table_present(target, SCANS_TABLE) else None
    finally:
        target.close()
        source.close()

    if integrity != "ok":
        backup_path.unlink(missing_ok=True)
        raise LifecycleError(f"backup failed integrity check ({integrity}); file removed")

    manifest: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "label": label,
        "tool": TOOL_NAME,
        "method": "sqlite3 online backup API (Connection.backup)",
        "source_database": str(source_path),
        "source_size_bytes": source_path.stat().st_size,
        "backup_path": str(backup_path),
        "backup_size_bytes": backup_path.stat().st_size,
        "backup_sha256": _sha256(backup_path),
        "row_count": rows,
        "integrity_check": integrity,
        "sqlite_version": sqlite3.sqlite_version,
        "schema": {
            "table": SCANS_TABLE,
            "required_columns": list(REQUIRED_COLUMNS),
            "optional_columns": list(OPTIONAL_COLUMNS),
        },
    }
    manifest_path = _manifest_path(backup_path)
    manifest["manifest_path"] = str(manifest_path)
    _write_json(manifest_path, manifest)
    return manifest


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def verify_backup(
    backup: Path | str,
    *,
    min_rows: int | None = None,
    expected_rows: int | None = None,
) -> dict[str, Any]:
    """Validate a backup file offline, without touching the live database.

    Checks: file present and non-empty, openable read-only, SQLite
    ``integrity_check``, ``scans`` table present, required columns present, row
    count readable, optional expected/minimum row counts, and -- when the
    ``.db.json`` manifest written by ``backup`` is present -- a SHA-256 and row
    count match against it.
    """
    path = _as_path(backup)
    checks: list[dict[str, Any]] = []
    manifest_path = _manifest_path(path)
    # Fixed-shape payload: every early return still reports the same keys, so a
    # caller can index the result without checking which check failed first.
    payload: dict[str, Any] = {
        "backup": str(path),
        "manifest_path": str(manifest_path),
        "manifest_present": manifest_path.is_file(),
        "checksum_verified": False,
        "row_count": None,
    }

    def check(name: str, ok: bool, detail: str) -> bool:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def result() -> dict[str, Any]:
        payload["checks"] = checks
        payload["ok"] = all(item["ok"] for item in checks)
        return payload

    if not check("file_exists", path.is_file(), str(path)):
        return result()
    check("file_non_empty", path.stat().st_size > 0, f"{path.stat().st_size} bytes")

    try:
        connection = _connect_readonly(path)
    except sqlite3.Error as exc:
        check("open_readonly", False, str(exc))
        return result()
    check("open_readonly", True, "opened with mode=ro")

    rows: int | None = None
    try:
        integrity = _integrity_check(connection)
        if not check("integrity_check", integrity == "ok", integrity):
            # A file that fails integrity_check is not a usable database; the
            # schema probes below would only raise on it.
            return result()
        present = _table_present(connection, SCANS_TABLE)
        check("scans_table_present", present, SCANS_TABLE)
        columns = _columns(connection) if present else []
        missing = [name for name in REQUIRED_COLUMNS if name not in columns]
        check(
            "required_columns",
            not missing,
            f"missing: {missing}" if missing else f"{len(columns)} columns present",
        )
        if present and not missing:
            rows = _row_count(connection)
            check("row_count_readable", True, f"{rows} rows")
    except sqlite3.Error as exc:
        check("schema_readable", False, str(exc))
    finally:
        connection.close()

    if rows is not None and min_rows is not None:
        check("min_rows", rows >= min_rows, f"{rows} >= {min_rows}")
    if rows is not None and expected_rows is not None:
        check("expected_rows", rows == expected_rows, f"{rows} == {expected_rows}")
    payload["row_count"] = rows

    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            check("manifest_readable", False, str(exc))
        else:
            recorded = manifest.get("backup_sha256")
            actual = _sha256(path)
            payload["checksum_verified"] = True
            check("manifest_checksum", recorded == actual, f"recorded={recorded} actual={actual}")
            if rows is not None and manifest.get("row_count") is not None:
                check("manifest_row_count", manifest["row_count"] == rows,
                      f"recorded={manifest['row_count']} actual={rows}")
    else:
        checks.append({
            "check": "manifest_checksum",
            "ok": True,
            "detail": f"no manifest at {manifest_path}; checksum not verified",
        })

    return result()


# --------------------------------------------------------------------------- #
# restore
# --------------------------------------------------------------------------- #
def restore_database(
    backup: Path | str,
    target: Path | str,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Restore ``backup`` into the explicit ``target`` path.

    The backup is verified first and a failed verification aborts the restore.
    An existing target is never destroyed: without ``force`` the operation is
    refused, and with ``force`` the existing file is moved aside to
    ``<target>.replaced-<timestamp>`` before the copy.

    Stop the server before restoring over the database it is using; SQLite has
    no way to make a running process pick up a replaced file.
    """
    backup_path = _as_path(backup)
    target_path = _as_path(target)
    if not backup_path.is_file():
        raise LifecycleError(f"backup not found: {backup_path}")
    if target_path.resolve() == backup_path.resolve():
        raise LifecycleError("target and backup are the same file")

    verification = verify_backup(backup_path)
    if not verification["ok"]:
        failed = [item["check"] for item in verification["checks"] if not item["ok"]]
        raise LifecycleError(f"refusing to restore: backup failed verification ({failed})")

    replaced: Path | None = None
    if target_path.exists():
        if not force:
            raise LifecycleError(
                f"target exists (use --force to replace it): {target_path}"
            )
        replaced = target_path.with_name(f"{target_path.name}.replaced-{_utc_stamp()}")
        target_path.replace(replaced)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    source = _connect_readonly(backup_path)
    destination = sqlite3.connect(target_path)
    try:
        destination.row_factory = sqlite3.Row
        # Same consistent-copy mechanism as backup_database, in reverse.
        source.backup(destination)
        destination.commit()
        integrity = _integrity_check(destination)
        restored_rows = (
            _row_count(destination) if _table_present(destination, SCANS_TABLE) else None
        )
    finally:
        destination.close()
        source.close()

    if integrity != "ok":
        raise LifecycleError(
            f"restored file failed integrity check ({integrity}); "
            f"the previous file, if any, is at {replaced}"
        )

    return {
        "backup": str(backup_path),
        "target": str(target_path),
        "restored": True,
        "replaced_file": str(replaced) if replaced else None,
        "row_count": restored_rows,
        "integrity_check": integrity,
        "verified_against_backup": restored_rows == verification.get("row_count"),
        "reminder": "restart the service after restoring; verify with `info --database <target>`",
    }


# --------------------------------------------------------------------------- #
# retention-plan (report only -- there is no delete code path)
# --------------------------------------------------------------------------- #
def retention_plan(
    database: Path | str,
    *,
    keep: int | None = None,
    older_than_days: int | None = None,
    sample: int = 20,
) -> dict[str, Any]:
    """Report what a retention policy *would* remove. Never deletes anything.

    ``keep`` keeps the newest N rows (recency = row id, matching the app's
    ``ORDER BY id DESC`` history ordering); ``older_than_days`` matches rows
    whose ``created_at`` is older than the cutoff. If both are given the
    intersection is reported. Neither option deletes; there is no code here that
    can remove a row.
    """
    if keep is None and older_than_days is None:
        raise LifecycleError("specify --keep and/or --older-than-days")

    path = _as_path(database)
    if not path.is_file():
        raise LifecycleError(f"database not found: {path}")

    connection = _connect_readonly(path)
    try:
        if not _table_present(connection, SCANS_TABLE):
            raise LifecycleError(f"no {SCANS_TABLE!r} table in {path}")
        total = _row_count(connection)

        # Only internal constants are interpolated; every value is a bound
        # parameter (the same rule app/database.py follows).
        clauses: list[str] = []
        params: list[Any] = []
        if keep is not None:
            if keep < 0:
                raise LifecycleError("--keep must be >= 0")
            if keep == 0:
                clauses.append("1 = 1")
            else:
                oldest_kept = connection.execute(
                    f"SELECT MIN(id) FROM (SELECT id FROM {SCANS_TABLE} ORDER BY id DESC LIMIT ?)",
                    (keep,),
                ).fetchone()[0]
                if oldest_kept is None:
                    clauses.append("0 = 1")  # fewer rows than `keep`: nothing to remove
                else:
                    clauses.append("id < ?")
                    params.append(oldest_kept)
        if older_than_days is not None:
            if older_than_days < 0:
                raise LifecycleError("--older-than-days must be >= 0")
            cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
            clauses.append("created_at < ?")
            params.append(cutoff)

        where = " AND ".join(clauses) if clauses else "0 = 1"
        candidates = int(
            connection.execute(
                f"SELECT COUNT(*) FROM {SCANS_TABLE} WHERE {where}", params
            ).fetchone()[0]
        )
        sample_ids = [
            int(row[0])
            for row in connection.execute(
                f"SELECT id FROM {SCANS_TABLE} WHERE {where} ORDER BY id LIMIT ?",
                (*params, int(sample)),
            ).fetchall()
        ]
    finally:
        connection.close()

    size_bytes = path.stat().st_size
    return {
        "database": str(path),
        "total_rows": total,
        "policy": {"keep_newest": keep, "older_than_days": older_than_days},
        "would_remove": candidates,
        "would_keep": total - candidates,
        "sample_removed_ids": sample_ids,
        "estimated_bytes_reclaimed": int(size_bytes * (candidates / total)) if total else 0,
        "deletion_implemented": False,
        "note": (
            "Report only. This tool contains no delete code path. Enabling a "
            "retention policy is an unresolved product decision; see "
            "ops/README.md and eval/DAY12_REPORT.md."
        ),
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="db_lifecycle.py",
        description=(
            "PhishGuard database lifecycle tooling: inspect, back up, verify, "
            "restore, and plan retention. Read-only unless you run 'restore'."
        ),
    )

    def add_database_option(target: argparse.ArgumentParser, *, subcommand: bool) -> None:
        """Accept ``--database`` before OR after the subcommand.

        The copies on the subcommands use ``SUPPRESS`` so that, when the flag is
        not given after the subcommand, argparse does not overwrite the value
        parsed before it with ``None``.
        """
        target.add_argument(
            "--database",
            type=Path,
            default=argparse.SUPPRESS if subcommand else None,
            help="database file (default: the path the application is configured to use)",
        )

    add_database_option(parser, subcommand=False)
    sub = parser.add_subparsers(dest="command", required=True)

    info = sub.add_parser("info", help="describe the database (read-only)")
    add_database_option(info, subcommand=True)

    backup = sub.add_parser("backup", help="write a consistent snapshot (online backup API)")
    add_database_option(backup, subcommand=True)
    backup.add_argument("--output-dir", type=Path, default=None,
                        help="destination directory (default: <database dir>/backups)")
    backup.add_argument("--label", default=None, help="free-text note stored in the manifest")
    backup.add_argument("--stamp", default=None,
                        help="override the UTC timestamp used in the file name")
    backup.add_argument("--force", action="store_true", help="replace an existing backup file")

    verify = sub.add_parser("verify", help="validate a backup file offline (read-only)")
    verify.add_argument("--backup", type=Path, required=True, help="backup file to verify")
    verify.add_argument("--min-rows", type=int, default=None)
    verify.add_argument("--expected-rows", type=int, default=None)

    restore = sub.add_parser("restore", help="copy a verified backup to an explicit target path")
    restore.add_argument("--backup", type=Path, required=True)
    restore.add_argument("--target", type=Path, required=True)
    restore.add_argument("--force", action="store_true",
                         help="move an existing target aside and write over it")

    plan = sub.add_parser("retention-plan",
                          help="report rows a retention policy WOULD remove (never deletes)")
    add_database_option(plan, subcommand=True)
    plan.add_argument("--keep", type=int, default=None, help="keep the newest N rows")
    plan.add_argument("--older-than-days", type=int, default=None,
                      help="match rows created more than N days ago")
    plan.add_argument("--sample", type=int, default=20, help="ids to list (default 20)")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. 0 = success, 1 = refusal/failure."""
    args = _build_parser().parse_args(argv)
    # `--database` may appear before or after the subcommand; the subcommand copy
    # uses SUPPRESS so it never overwrites a value parsed earlier with None.
    database = args.database if args.database is not None else default_database_path()

    try:
        if args.command == "info":
            payload: dict[str, Any] = database_info(database)
        elif args.command == "backup":
            payload = backup_database(
                database,
                output_dir=args.output_dir,
                force=args.force,
                label=args.label,
                stamp=args.stamp,
            )
        elif args.command == "verify":
            payload = verify_backup(
                args.backup, min_rows=args.min_rows, expected_rows=args.expected_rows
            )
        elif args.command == "restore":
            payload = restore_database(args.backup, args.target, force=args.force)
        elif args.command == "retention-plan":
            payload = retention_plan(
                database,
                keep=args.keep,
                older_than_days=args.older_than_days,
                sample=args.sample,
            )
        else:  # pragma: no cover - argparse enforces the choices
            raise LifecycleError(f"unknown command: {args.command}")
    except LifecycleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.command == "verify":
        return 0 if payload["ok"] else 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
