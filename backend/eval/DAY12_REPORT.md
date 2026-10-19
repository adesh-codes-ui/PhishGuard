# Day 12: Deployment Artifacts and Data Lifecycle

**Scope:** a local, code-level audit of the SQLite persistence layer and the
deployment surface, followed by (a) new database backup/verify/restore tooling
with tests, (b) report-only retention planning, and (c) reviewed deployment
templates for a single-worker service behind a TLS-terminating reverse proxy.

This is **not** a penetration test, and it does not verify a production
deployment. **No reverse proxy, service manager, TLS certificate or Linux host
was available on this machine**, so none of the deployment templates was syntax-
validated or executed. Every claim below is backed by code reading, a test, or an
observed local run against a throwaway database.

**Baseline:** 240 tests passed, 1 warning (Day 11).
**After:** 312 tests passed, 1 warning. Frontend production build unchanged.

Unchanged by design:

- heuristic scoring and the production bands (Low 0-24 / Medium 25-49 / High
  50-74 / Critical 75-100),
- the HTTP API contract and the frontend/API contract,
- `app/analyzer.py`, `app/security.py`, `app/schemas.py`,
  `app/providers/virustotal.py`, `app/main.py`, `app/config.py`,
  `app/database.py` (no application source was modified on Day 12),
- `requirements.txt` (no new dependency) and every previous day report,
- the Day 9 real-dataset evaluation status (still blocked; see §10).

## 1. What was audited

`app/database.py`, `app/config.py`, `app/security.py`, `app/main.py`,
`.gitignore`, `README.md`, `backend/.env.example`, `tests/*`,
`eval/DAY11_REPORT.md` (its §6 "operational limits" is the input to this day),
and the absence of any deployment artifact in the repository. Tool availability
was probed explicitly (`nginx`, `caddy`, `docker`, `podman`, `sqlite3`, `openssl`,
`systemd-analyze`, WSL): none present.

## 2. Findings before any change

### D1 (High, operational) - no backup, no restore, no integrity check exists

Day 11 (§6.5) recorded "no backup/restore mechanism". In practice the only
option an operator had was copying `phisguard.db` with the operating system
while uvicorn was writing to it, which is exactly the unsafe case: an OS copy
ignores SQLite's locking protocol and can capture a torn or stale snapshot (and
misses committed pages held in a `-wal` file once WAL is ever enabled). There was
also no way to confirm a copy was a valid database before relying on it.

### D2 (High, security/product) - `/api/history` is unauthenticated

Re-confirmed, not fixed. `GET /api/history` and `/api/history/{id}` return every
URL analyzed on the instance - private hostnames, tokens in query strings, or
anything a user pasted - to anyone who can reach the port. `POST /api/analyze`
is anonymous too, so it can be used to burn CPU and, if enrichment is enabled,
the VirusTotal quota. This is a product decision (there is no user model), so it
is documented rather than guessed at; see §6.

### D3 (Medium) - unbounded growth with no retention decision

Every analysis inserts a row forever. Nothing prunes or archives. Deleting scan
history is destructive and was deliberately left unimplemented; what was missing
was a way to *see the size of the problem* before deciding.

### D4 (Medium) - the only "health check" is unauthenticated and runs `COUNT(*)`

`/api/health` is fine as a liveness probe but must not be the public ingress: it
is unauthenticated and runs `COUNT(*)`, so a public uptime monitor is both an
information leak and a cheap way to make the server do work. Nothing in the
repository said where probes should point, or warned against publishing it.

### D5 (Medium) - the trusted-proxy story was prose only

The application deliberately never trusts `X-Forwarded-For` for rate limiting
(verified in `app/security.py::client_identifier`), and uvicorn only honours
`X-Forwarded-*` with `--proxy-headers --forwarded-allow-ips=...`. Day 11 §4
recommended this, but there was no artifact that actually set it, so the
"correct" configuration was easy to get wrong (or to leave trusting everything).

### D6 (Low) - the new tool rejected `info --database <path>`

Found by using the tool, not by reading it: `--database` was declared only on the
top-level parser, so the natural invocation `db_lifecycle.py info --database X`
exited **2** with an argparse usage error while
`db_lifecycle.py --database X info` worked. Confusing, and likely to be
mis-diagnosed as "database not found". Fixed (§3.1).

### D7 (Low) - `verify` returned a different payload shape on early failure

When a file failed before the schema checks, `verify` returned a dict **without**
`row_count`, `manifest_present` or `checksum_verified`, so a caller indexing the
result crashed (`KeyError`) instead of reading a failed check. Fixed (§3.1).

### D8 (Low) - a non-SQLite file raised an unhandled `sqlite3.DatabaseError`

`verify`/`info` probed `sqlite_master` before checking whether the file was a
database at all, so a truncated or garbage file produced a traceback rather than
a clean "integrity_check failed" verdict. Fixed (§3.1).

### D9 (Low, privacy hygiene) - `.gitignore` did not cover backups or sidecars

`*.db` was ignored, but `phisguard.db-wal`, `phisguard.db-shm`, a `.db.json`
manifest and a `backups/` directory were not. A backup (or a manifest) contains
analyzed URLs and could have been committed accidentally. Fixed (§3.4).

### Verified correct (no change needed)

| Area | Finding |
| --- | --- |
| SQLite access | every statement parameterized; `init_db()` is `CREATE TABLE IF NOT EXISTS` + additive `ALTER TABLE`, idempotent, never destructive. |
| Database path | `Settings.resolved_database_path` is the single rule (relative -> `backend/`); the new tool reuses it rather than duplicating it. |
| Journal mode | the application applies no `journal_mode`/`busy_timeout` pragma, so databases are rollback-journal (`delete`) by default; live `info` confirmed `journal_mode=delete`, no `-wal` file. The backup tool therefore had to be correct for *both* modes (tested in WAL, exercised live in delete mode). |
| Analyze/history endpoints | unchanged; live run returned the same bands (phishing-shaped URL -> 80 Critical, benign -> 15 Low) and `threat_intel.status=disabled` with no outbound call. |
| Local development flow | unchanged and verified live: `uvicorn app.main:app` still boots and serves `/api/health`, `/api/analyze`, `/api/history`. |
| Frontend | untouched; rebuild produced identical asset sizes (35 modules). |

## 3. Changes made

### 3.1 `backend/ops/db_lifecycle.py` (new)

Standard-library-only CLI with five subcommands; read-only unless `restore` is
explicitly run.

- `info` - describes a database (size, `journal_mode`, `PRAGMA integrity_check`,
  row count, oldest/newest `created_at`, columns, presence of `-wal`/`-shm`/
  `-journal` sidecars). Opening a *missing* file never creates it.
- `backup` - snapshot via **SQLite's online backup API**
  (`sqlite3.Connection.backup`), which reads through SQLite's locking protocol
  and therefore accounts for a live database's journal/WAL state. Writes a
  `.db.json` manifest containing a SHA-256 of the backup, row count, SQLite
  version and the expected schema. Refuses to overwrite without `--force`, and
  deletes the output if the snapshot fails `integrity_check`.
- `verify` - read-only (`mode=ro`) validation: file present/non-empty, openable,
  `integrity_check`, `scans` table, required columns, row count, optional
  `--min-rows`/`--expected-rows`, and manifest SHA-256 + row-count match when the
  manifest is present. Fixed-shape result in every path (D7).
- `restore` - verifies the backup **first**, writes only to an explicit
  `--target`, refuses an existing target without `--force`, and moves the
  previous file to `<name>.replaced-<timestamp>` instead of destroying it.
- `retention-plan` - reports `total_rows`, `would_remove`, `would_keep`, sample
  ids and an estimated reclaimed size. **Contains no delete code path at all**
  (guarded by a test that greps the source for `DELETE FROM` et al.).

Also fixes D6 (option accepted before *or* after the subcommand, via a
`SUPPRESS`-defaulted copy of the argument on the subparsers) and D8 (integrity
failure short-circuits; unreadable files are reported, not raised).

Uses Python's bundled SQLite (3.49.1 under Python 3.12.10) rather than a
`sqlite3` binary, which is not installed on this machine.

### 3.2 `backend/ops/__init__.py`, `backend/ops/README.md` (new)

The runbook: safety contract, where the database lives and why it needs a
persistent volume, the backup/verify/restore procedure (including restoring into
a **separate** validation database first), the retention options table, and the
growth / locking / privacy / recovery limitations.

### 3.3 `backend/tests/test_ops_db_lifecycle.py` (new, 42 tests)

All against disposable `tmp_path` databases. Backup from a **live WAL database
with an open writer**; manifest SHA-256 and row count; refusal to overwrite;
verify accepting a good backup and rejecting a non-database file, an empty file,
a file without the `scans` table, a file missing a required column, and a
post-backup tamper; manifest-checksum mismatch; `--min-rows`/`--expected-rows`;
restore into a separate target leaving the source byte-identical; restore
refusing an existing target and preserving the replaced file; refusal of an
invalid backup and of target==backup; retention-plan counts, `--keep 0`,
keep-larger-than-table, age-based, combined-policy intersection, negative-value
rejection, and proof that the live row count is unchanged after planning; the
no-delete-source guard; schema-drift guard against `app.database._SCHEMA`;
`default_database_path()` following application settings; CLI exit codes; both
`--database` placements; `.gitignore` coverage.

### 3.4 `backend/tests/test_deploy_artifacts.py` (new, 30 tests)

Pins the templates to the application's real configuration (see §7 for exactly
what these do and do not prove).

### 3.5 `deploy/` (new)

- `deploy/README.md` - what the deployment looks like and why (one worker, one
  SQLite file), placeholders table, install outline, environment table, health
  checks, startup/shutdown/upgrade/restart, backup integration, the **history
  access** options table, explicit trusted-proxy assumptions, "local development
  is unchanged", and what is deliberately not provided (no Docker/Compose, no
  multi-worker, no CI, no secret manager, no in-app TLS).
- `deploy/phisguard.service` - systemd unit: `--workers 1`, `--host 127.0.0.1`,
  `StateDirectory=phisguard` (persistent `/var/lib/phisguard`),
  `EnvironmentFile=/etc/phisguard/phishguard.env`, `Restart=on-failure`,
  `TimeoutStopSec=30`, a modest hardening block, and explicit
  `--proxy-headers --forwarded-allow-ips=127.0.0.1`.
- `deploy/phishguard.env.example` - production configuration: `environment=
  production`, absolute persistent `PHISHGUARD_DATABASE_PATH`, explicit HTTPS
  CORS origin, body cap, rate limiter left off (the proxy owns it), VirusTotal
  left **off** for an offline default, and a closing reminder that the API has no
  authentication.
- `deploy/nginx-phisguard.conf.example` - TLS termination, HTTP->HTTPS redirect,
  `client_max_body_size 16k` (equal to the app default), a **shared**
  `limit_req_zone` keyed on `$binary_remote_addr` declared in the http context,
  proxy timeouts above the VirusTotal timeout, `X-Forwarded-For`
  **overwritten** (never blindly forwarded), same-origin static frontend, and a
  commented basic-auth block for `/api/history`.
- `deploy/Caddyfile.example` - Caddy alternative (automatic TLS, body cap), with
  an explicit warning that Caddy has **no built-in rate limiter** and that the
  commented limiter requires the third-party `caddy-ratelimit` module.

### 3.6 `.gitignore` (modified)

Added `*.db-wal`, `*.db-shm`, `*.db.json`, and `backups/` (D9).

### 3.7 `README.md` (modified)

New "Deployment and data lifecycle" section (templates, backup/verify commands,
restore-into-a-separate-path rule, report-only retention, and an unauthenticated-
history warning), `ops/` and `deploy/` in the project-structure tree,
`unauthenticated` markers on the two history rows in the API table, and updated
"Known limitations" (no authentication; unbounded history; single writer; no
point-in-time recovery).

### 3.8 `backend/eval/DAY12_REPORT.md` (new)

This report. No previous day report was modified.

### Deliberately not changed

No application source file, no scoring threshold, no API/response shape, no new
dependency, no WAL/`busy_timeout` pragma, no auth scaffolding, no retention
deletion, no Docker artifact, and no dataset acquisition.

## 4. Backup and restore design

**Why the online backup API and not a file copy.** `sqlite3.Connection.backup`
copies pages through SQLite itself: it takes the appropriate locks, reads a
consistent snapshot, and includes committed data that lives in a `-wal` file when
WAL is in use. An OS copy of a file being written can capture a torn snapshot.
It also works without stopping the server, which is what makes a nightly job
practical.

**Procedure** (full text in `backend/ops/README.md`):

1. `info` - confirm the path, row count and integrity.
2. `backup --label <reason>` - snapshot into `<db dir>/backups/`, plus manifest.
3. `verify --backup <file>` - exit 0 = every check passed.
4. Copy the `.db` **and** `.db.json` off-host, encrypted.
5. To restore: stop the service, restore into a **separate** path, validate that
   copy with `info`/`verify`, then restore over the live path with `--force`
   (which preserves the old file as `<name>.replaced-<timestamp>`), restart, and
   check `/api/health`.

**Retention is not enabled.** `retention-plan` reports only. See §5.

## 5. Retention: options and the unresolved decision

Measured reality: the `scans` table grows by one row per `POST /api/analyze`,
with no bound. `retention-plan` makes that visible
(`--keep N` and/or `--older-than-days D`; combined = intersection).

| Option | Effect | Trade-off |
| --- | --- | --- |
| No retention (current) | nothing is ever removed | file grows forever; `/api/health`'s `COUNT(*)` and history listing slow down; backups grow |
| Keep newest N rows | bounded size, no timestamps involved | silently discards older history even if recent; N must be chosen against real traffic |
| Drop rows older than N days | matches an age-based retention promise | needs a stated period; interacts with compliance |
| Archive then prune | keeps old data cheaply | second storage/format decision plus a privacy story for that copy |

**Unresolved decision (product):** whether PhishGuard retains history at all,
for how long, and who may delete it. Two constraints were adopted regardless:
deletion must be explicit and operator-driven (never a deploy side effect), and a
pre-change backup must be taken first (a later backup encodes the prune). Until
that decision is made, **no deletion is implemented** - and the tool is
structurally incapable of it.

## 6. History access: options and the unresolved decision

| Option | Change | Cost / limitation |
| --- | --- | --- |
| Keep it off the public internet (private network/VPN) | none | recommended for the current build; not usable as a public service |
| Authenticate at the reverse proxy (basic auth / mTLS / SSO in front of `/api/history*`) | proxy config only | protects that data, but the API itself stays anonymous - anyone reaching the port directly bypasses it; only safe together with the loopback bind and a single ingress path |
| Add application authentication | new scope: user model, sessions/tokens, ownership, tests | the correct long-term answer; explicitly out of scope |
| Disable history entirely | guard/remove the routes | removes a feature; a product call |

**Unresolved decision (product):** whether PhishGuard ever holds user-specific
history, and if so who may read it. No authentication was invented. The
deployment templates keep the app bound to loopback, document proxy-side
authentication, and state plainly that they do **not** make a publicly reachable,
unauthenticated API safe.

## 7. Deployment artifacts and what validation actually happened

Available on this machine: **none** of `nginx`, `caddy`, `docker`, `podman`,
`sqlite3`, `openssl`, `systemd-analyze`; WSL is not installed. No system-level
tooling was installed (that would be both out of scope and unverifiable here).

| Check | Status |
| --- | --- |
| `nginx -t` against `deploy/nginx-phisguard.conf.example` | **unverified** - no nginx binary |
| `caddy validate` against `deploy/Caddyfile.example` | **unverified** - no caddy binary |
| `systemd-analyze verify` against `deploy/phisguard.service` | **unverified** - no systemd |
| TLS certificate issuance / HTTPS reachability | **not attempted** |
| Container build/run | **not provided and not attempted** |
| Running any template on a real host | **not performed** |

Instead, 30 static checks (`tests/test_deploy_artifacts.py`) verify that the
templates are *consistent with the application* and structurally sane:

- `client_max_body_size 16k` and Caddy's `max_size 16KB` both equal
  `Settings.max_request_body_bytes` (16384) - so the proxy cannot be the looser
  limit;
- `limit_req_zone` is keyed on `$binary_remote_addr` and declared **before** the
  first `server` block (http context, the only place nginx accepts it);
- `listen 443 ssl` + `return 301 https://` + documented `ssl_certificate`/certbot
  paths (certificate files are placeholders and must exist before nginx starts);
- no client-supplied `X-Forwarded-For` is ever passed through;
- the unit runs exactly `--workers 1` on `127.0.0.1`, keeps the database on
  `StateDirectory=phisguard` (`/var/lib/phisguard/....db`), loads
  `/etc/phisguard/phishguard.env`, restarts on failure, sets a stop timeout, and
  enables the explicit trusted-proxy flags;
- **every** `PHISHGUARD_*` key in `deploy/phishguard.env.example` and
  `backend/.env.example` maps to a real, *read* setting (`Settings.model_fields`,
  honouring `validation_alias`) - the "documented but inert variable" bug class
  from Day 11 cannot reappear in these files;
- production files set `environment=production`, never a wildcard CORS origin,
  never `docs_enabled=true`, and use an explicit `https://` origin;
- nginx/all deployment files are brace-balanced and terminated; the unit parses
  as INI with `[Unit]`/`[Service]`/`[Install]`.

These are lint/consistency checks. They are **not** syntax validation by the real
tools and do not prove that a deployment works. Each artifact also states its own
validation status in its header comment.

## 8. Verification actually performed

### 8.1 Backend suite (canonical environment)

```
cd backend
.\.venv\Scripts\python.exe -m pytest
=> 312 passed, 1 warning in 6.43s
```

Baseline was 240; the delta is 72 new tests (ops 42, deploy 30). Per file:
analyzer 124, virustotal 21, api 20, config 30, dataset_import 23, security 14,
ops 42 (new), deploy 30 (new), database 3, eval 3, thresholds 2.

The single warning is the pre-existing `StarletteDeprecationWarning: Using httpx
with starlette.testclient is deprecated; install httpx2 instead`
(`fastapi/testclient.py`). No new warning was introduced.

Re-run from a hostile shell (ambient `VIRUSTOTAL_API_KEY`,
`PHISHGUARD_LOG_LEVEL=debug`, `PHISHGUARD_CORS_ORIGINS=*`,
`PHISHGUARD_ENVIRONMENT=production`, `PHISHGUARD_DATABASE_PATH=<bogus>`):

```
=> 312 passed, 1 warning in 5.60s     (identical, thanks to tests/conftest.py)
```

### 8.2 Lifecycle CLI walkthrough (disposable database seeded by the application)

Database created with `app.database.init_db()` + `save_scan()` at a temporary
path; the project's real `backend/phisguard.db` was never opened. Condensed
observed output:

| Command | Exit | Observed |
| --- | --- | --- |
| `db_lifecycle.py info` (no `--database`; uses app config) | 0 | `exists=true row_count=5 journal_mode=delete integrity_ok=true` |
| `... backup --label day12-evidence` | 0 | backup + manifest written, `row_count=5 integrity_check=ok`, SHA-256 recorded |
| `... verify --backup <backup> --expected-rows 5` | 0 | `ok=true checksum_verified=true manifest_present=true` |
| `... restore --backup <backup> --target restore-validation.db` | 0 | `restored=true row_count=5 verified_against_backup=true replaced_file=null` |
| `... info --database restore-validation.db` (flag after subcommand) | 0 | `row_count=5 integrity_ok=true missing_required_columns=[]` |
| `... restore ...` again (target exists, no `--force`) | 1 | `error: target exists (use --force to replace it)` |
| `... retention-plan --keep 2` | 0 | `would_remove=3 would_keep=2 deletion_implemented=false` |
| `... info` after planning | 0 | `row_count=5` (unchanged - nothing was deleted) |
| `... verify --backup truncated.db` | 1 | failed checks `['integrity_check']` |

The project's `backend/phisguard.db` hash was identical before and after.

### 8.3 Live server + backup of a database in use

Started the real API (`uvicorn app.main:app`, temporary database,
`PHISHGUARD_VIRUSTOTAL_ENABLED=false`, no key in the environment):

```
GET  /api/health   : 200 {'status': 'ok', 'version': '0.1.0', 'scans_stored': 0}
POST /api/analyze  : 200 id=1 risk=80 (Critical) intel=disabled
POST /api/analyze  : 200 id=2 risk=15 (Low)      intel=disabled
GET  /api/history  : 200 total=2
```

Then, **while the server was still running**, the lifecycle tool was pointed at
that same file:

```
[exit 0] info   (server running): rows=2 journal_mode=delete integrity=ok wal=False
[exit 0] backup --label live-server: backup rows=2 size=16384B integrity=ok
[exit 0] verify --expected-rows 2: ok=True
         snapshot URLs: ['http://paypal.com.secure-login.evil.net/verify',
                         'https://www.example.com/login']
```

Two things this demonstrates: analyzer bands are untouched (80 Critical / 15
Low), and the online backup captured a consistent, independently verifiable
snapshot of a database that a live server was writing to. The server log
contains no secret and the project's own database hash is unchanged
(`project database unchanged: True`). The server was terminated afterwards and
port 8031 left with no listening socket.

### 8.4 Frontend production build

```
cd frontend
npm run build
=> tsc -b && vite build
   35 modules transformed
   dist/assets/index-*.css   29.77 kB │ gzip:  5.92 kB
   dist/assets/index-*.js   278.50 kB │ gzip: 87.59 kB
```

Identical to Day 11 (no frontend file was touched).

### 8.5 Day 9 status (unchanged, still blocked)

Real-dataset evaluation remains blocked: no `backend/eval/data/` directory and no
PhishTank/Tranco files exist. **No real-world metric is claimed anywhere on Day
12.** Acquisition steps and their caveats stay in `eval/DAY9_REPORT.md` §5 and
`eval/DATASETS.md`.

## 9. Implemented safeguards vs recommendations

**Implemented and tested (this day):**

- consistent backups via SQLite's online backup API, with a SHA-256 manifest;
- read-only verification of a backup (integrity, schema, row counts, checksum),
  validated on a corrupted file and on a manifest mismatch;
- a restore that verifies first, writes only to an explicit target, refuses to
  overwrite without `--force`, and preserves the replaced file;
- retention *planning* with no delete code path (guarded by a test);
- `.gitignore` coverage so backups/manifests/WAL sidecars are not committed;
- deployment templates whose body cap, worker count, database path, CORS origin,
  docs setting and environment keys are pinned to the application by tests;
- a single-worker unit bound to loopback with explicit trusted-proxy flags.

**Recommendations (documented, NOT implemented or verified):**

- terminate TLS at a proxy and manage certificates (`certbot`, or Caddy's
  automatic TLS) - no certificate was issued and no HTTPS was tested;
- require authentication for `/api/history` at the proxy, or keep the service
  private - the application still has no authentication;
- decide and then implement a retention policy (see §5);
- run the templates on a real host and validate them with `nginx -t` /
  `caddy validate` / `systemd-analyze verify`;
- move to a server database before scaling past one worker.

## 10. Remaining risks

1. **No authentication** on any endpoint, including history - the largest gap.
2. **The rate limiter is per process** (and off by default); only the proxy's
   shared `limit_req` is effective, and it was never exercised.
3. **SQLite single writer**, no WAL, no `busy_timeout` tuning; write contention
   surfaces as a generic 503.
4. **Unbounded history**, no retention (deliberately, pending a decision).
5. **No point-in-time recovery** - the last verified backup is the recovery
   point; a restore is whole-file.
6. **Backups contain every analyzed URL**, so they are as sensitive as the
   database and must be encrypted and access-controlled; nothing enforces that.
7. **Deployment templates are unvalidated** by their real tools (see §7).
8. **No application-level request timeout/concurrency cap**; a slow VirusTotal
   lookup occupies the single worker.
9. **`/api/health` runs `COUNT(*)`** on every probe and is unauthenticated.
10. **No rotation of the manifest/schema expectation**: if `app/database.py`'s
    schema changes, a test fails and the tool's `EXPECTED_COLUMNS` must be
    updated by hand (by design - it is the guard, not a gap).

## 11. Files changed

New:

- `backend/ops/__init__.py`
- `backend/ops/db_lifecycle.py`
- `backend/ops/README.md`
- `backend/tests/test_ops_db_lifecycle.py` (42 tests)
- `backend/tests/test_deploy_artifacts.py` (30 tests)
- `deploy/README.md`
- `deploy/phisguard.service`
- `deploy/phishguard.env.example`
- `deploy/nginx-phisguard.conf.example`
- `deploy/Caddyfile.example`
- `backend/eval/DAY12_REPORT.md`

Modified:

- `.gitignore` (backup / WAL-sidecar / manifest patterns)
- `README.md` (deployment + data-lifecycle section, API-table auth markers,
  limitations)

No application source file, `requirements.txt` or previous day report was
modified (confirmed by file timestamps: every application file and report
predates this session's first write).

## 12. Next milestone

Concrete, in the order the risks justify:

1. **Decide authentication for `POST /api/analyze` + `/api/history`** (the
   blocking product decision), then implement it or commit to the private-network
   deployment.
2. **Validate the deployment artifacts on a real Linux host** (`nginx -t`,
   `systemd-analyze verify`, a real certificate, then a restart and restore
   drill) - Day 12 produced the artifacts; nothing has run them.
3. **Decide retention** using `retention-plan` output against real traffic.
4. **Reconsider SQLite** (WAL + `busy_timeout`, or a server database) if
   concurrency ever exceeds one worker.

Still blocked from Day 9 and unchanged: real-data evaluation needs
`backend/eval/data/phishtank-online-valid.csv` and `tranco-top-1m.csv` placed by
hand (see `DAY9_REPORT.md` §5); no dataset was downloaded, resolved or submitted.
