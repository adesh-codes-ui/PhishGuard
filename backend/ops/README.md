# PhishGuard database lifecycle (`ops/`)

Operational tooling for the SQLite scan-history database. **Nothing here is
imported by the running server**, and nothing here touches the network.

```
backend/ops/db_lifecycle.py   # info | backup | verify | restore | retention-plan
```

Run it with the backend's virtual environment:

```powershell
cd backend
.\.venv\Scripts\python.exe ops\db_lifecycle.py info
```

## Safety contract

| Guarantee | How |
| --- | --- |
| Read-only unless you ask otherwise | `info` and `verify` never write; `verify` opens backup files with SQLite `mode=ro`. |
| No silent data loss | `restore` refuses to touch an existing file unless `--force`, and even then moves the old file to `<name>.replaced-<timestamp>` instead of deleting it. |
| No automatic deletion | `retention-plan` **reports** what a policy would remove. There is no delete code path in the tool at all. |
| Consistent snapshots | `backup` uses SQLite's online backup API (`sqlite3.Connection.backup`), which reads through SQLite's locking protocol and therefore accounts for a live database's journal/WAL state. An OS file copy can capture a torn or stale snapshot. |
| Tamper/rot detection | Every backup gets a `.db.json` manifest with a SHA-256, row count, SQLite version and schema expectation; `verify` checks them. |

## Where the database lives

`PHISHGUARD_DATABASE_PATH` (default `phisguard.db`) is resolved by
`Settings.resolved_database_path`: a relative value resolves against
`backend/`, an absolute value is used as-is. `db_lifecycle.py info` with no
arguments prints the path the *application* is configured to use, so the tool
and the server cannot disagree.

**Persistent-volume requirement.** In any deployment the database must live on
storage that survives restarts, redeploys and container rescheduling, and that
only the service user can read. The example unit in `deploy/` puts it at
`/var/lib/phisguard/phisguard.db` (created and owned by systemd via
`StateDirectory=phisguard`). A database under the code checkout or in a
container's writable layer is lost on the next deploy.

## 1. Inspect

```powershell
.\.venv\Scripts\python.exe ops\db_lifecycle.py info
```

Reports existence, size, `journal_mode`, `PRAGMA integrity_check`, row count,
oldest/newest `created_at`, the column list, and whether the `-wal`/`-shm`/
`-journal` sidecars are present.

## 2. Back up

```powershell
# -> backend/backups/phisguard-backup-<UTC timestamp>.db  (+ .db.json manifest)
.\.venv\Scripts\python.exe ops\db_lifecycle.py backup --label "pre-upgrade"
```

- The server does **not** need to be stopped; the online backup API takes a
  consistent snapshot of committed data.
- Backups are never written into the repository by default (`backups/` is
  git-ignored) and must never be committed: they contain every URL users have
  analyzed.
- Copy the produced `.db` **and** its `.db.json` to off-host storage
  (encrypted at rest, access-controlled). The `.db` alone is still restorable;
  the manifest is what makes `verify` able to detect corruption or tampering.
- A nightly schedule is enough for this workload, e.g.
  `0 2 * * * cd /opt/phisguard/backend && ./.venv/bin/python ops/db_lifecycle.py backup --label nightly`

## 3. Verify a backup

```powershell
.\.venv\Scripts\python.exe ops\db_lifecycle.py verify --backup backend\backups\phisguard-backup-20261019T020000Z.db
```

Exit code `0` means every check passed, `1` means at least one failed. Checks:
file present and non-empty, openable read-only, `PRAGMA integrity_check` = `ok`,
`scans` table present, required columns present, row count readable, and (when
the manifest is next to the backup) SHA-256 and row-count match. Use
`--min-rows`/`--expected-rows` to assert a known size.

## 4. Restore, and validate the restore

Restoring over the database a running server is using will not be picked up by
that process — **stop the service first** (see `deploy/README.md`).

```powershell
# 1. Stop the service (service manager or Ctrl+C).
# 2. Restore into a SEPARATE path first and validate it there.
.\.venv\Scripts\python.exe ops\db_lifecycle.py restore `
    --backup backend\backups\phisguard-backup-20261019T020000Z.db `
    --target %TEMP%\phisguard-restore-validation.db

# 3. Validate the restored copy independently.
.\.venv\Scripts\python.exe ops\db_lifecycle.py info   --database %TEMP%\phisguard-restore-validation.db
.\.venv\Scripts\python.exe ops\db_lifecycle.py verify --backup   %TEMP%\phisguard-restore-validation.db
```

`restore` verifies the backup **before** writing, reports whether the restored
row count matches the backup, and refuses to run at all if verification fails.

Only once the separate copy looks right, restore over the live path (the
previous file is preserved automatically):

```powershell
.\.venv\Scripts\python.exe ops\db_lifecycle.py restore `
    --backup backend\backups\phisguard-backup-20261019T020000Z.db `
    --target C:\path\to\phisguard.db --force
# -> previous file kept as phisguard.db.replaced-<UTC timestamp>

# 4. Restart the service and check GET /api/health.
```

If the restored copy is wrong, put the `.replaced-<timestamp>` file back and
restart.

## 5. Retention: options, not a policy

`GET /api/history` and the `scans` table grow without bound: every analysis
inserts a row forever. **No retention policy is implemented and no deletion
happens automatically.** `retention-plan` only reports:

```powershell
# What would be removed if only the newest 5000 rows were kept?
.\.venv\Scripts\python.exe ops\db_lifecycle.py retention-plan --keep 5000

# ...or if rows older than 180 days were dropped (or both: intersection)?
.\.venv\Scripts\python.exe ops\db_lifecycle.py retention-plan --older-than-days 180
```

Output includes totals, `would_remove`, `would_keep`, sample ids and an
**estimate** of reclaimed bytes, plus `"deletion_implemented": false`.

Options, with their trade-offs — the choice is a product decision, not a
technical one:

| Option | Effect | Trade-off |
| --- | --- | --- |
| No retention (current) | Nothing is ever removed. | The file grows forever; `/api/health`'s `COUNT(*)` and history listing get slower; backups get larger. |
| Keep newest N rows | Bounded size, simple to reason about, no timestamps involved. | Silently discards older scan history even if it is recent; "N" must be chosen against real traffic. |
| Drop rows older than N days | Matches a data-retention promise; age-based. | Depends on the client clock captured in `created_at` (UTC, server-generated at insert — so this is reliable here). |
| Archive then prune | Keeps old data somewhere cheaper. | Needs a second storage/format decision and a privacy story for that copy. |

Two constraints apply to **any** future decision:

1. Deletion must be opt-in and explicit (a documented operator action or a
   deliberately configured job), never a side effect of a deploy.
2. A backup taken *after* a prune encodes the prune. Enable retention only once
   the policy — and the deletion — has been signed off, and take a pre-change
   backup first.

Documented as an unresolved decision in `eval/DAY12_REPORT.md`.

## Limitations to plan around

- **SQLite single writer.** One writer at a time; concurrent writes surface as
  `database is locked`, which the API maps to a generic `503`. Run one
  application process against the file (`deploy/` does), and expect the write
  burst of `POST /api/analyze` to serialize.
- **No `busy_timeout`/WAL tuning** is applied by the application; the connection
  uses SQLite's defaults.
- **Growth.** See above.
- **Privacy.** The table stores the raw and normalized URL of everything
  analyzed, plus the host and findings — potentially personal or sensitive
  (search terms, private hosts on a LAN, tokens in query strings). Anyone with
  filesystem access, anyone with a backup, and anyone who can reach
  `GET /api/history` can read it. Backups must be encrypted and access
  controlled, and retention/deletion may be a compliance requirement.
- **Recovery time.** SQLite gives no point-in-time recovery: the best you have
  is the last verified backup. Restore is a whole-file operation, so anything
  written after the snapshot is lost.
- **Backup consistency is per-file.** A backup is one database snapshot; it does
  not include `.env`, the reverse-proxy config, or the frontend build. Back up
  configuration separately (it contains no secrets in this repository).
