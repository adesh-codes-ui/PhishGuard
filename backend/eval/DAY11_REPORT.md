# Day 11: Deployment Readiness and Configuration Audit

**Scope:** a local, code-level audit of configuration, startup behavior, CORS,
request protections and SQLite operations, plus executable verification against
real `uvicorn` processes and the built frontend.

This is **not** a penetration test and does not prove production security: there
was no fuzzing, no load testing, no external scanning and no third-party
network traffic of any kind. Every claim below is backed by code reading, a test,
or an observed local run.

**Baseline:** 207 tests passed, 1 warning (Day 10).
**After:** 240 tests passed, 1 warning. Frontend production build succeeds.

Unchanged by design:

- heuristic scoring and the production bands (Low 0-24 / Medium 25-49 / High
  50-74 / Critical 75-100, `app/analyzer.py::_classify`),
- the HTTP API shape (`/api/health`, `/api/analyze`, `/api/history`,
  `/api/history/{id}`) and the frontend/API contract,
- `requirements.txt` (no new dependency) and the Day 10 hardening behavior,
- the Day 9 dataset evaluation status (still blocked: no real dataset present).

## 1. What was audited

`app/config.py`, `app/main.py`, `app/security.py`, `app/database.py`,
`app/providers/virustotal.py`, `backend/.env.example`, `tests/*`,
`frontend/src/api/client.ts`, `frontend/.env.example`, `frontend/vite.config.ts`,
`frontend/package.json`, `README.md`, `.gitignore`, `backend/eval/DAY10_REPORT.md`.

## 2. Findings before any change

### F1 (High) — the `.env` file was resolved from the process working directory

`SettingsConfigDict(env_file=".env")` is relative, so pydantic-settings resolved
it against the CWD, not against `backend/`. Evidence (probe run with the app on
`sys.path` but CWD set to an unrelated directory containing its own `.env`):

```
CWD                    = C:\Users\...\Temp\phisguard-day11-cwd-ui9h_s1m
cwd .env present       = True
effective log_level    = debug          <-- the unrelated .env was used
configured env_file    = .env
```

Two real consequences: the operator's `backend/.env` is **silently ignored** when
the process is started from anywhere else (so a production CORS/DB override can
appear to be applied while having no effect), and an unrelated `.env` in some
other directory can be read instead.

### F2 (High) — no notion of an environment; production could silently inherit development settings

There was no environment flag at all. Consequences:

- `/docs`, `/redoc` and `/openapi.json` were always exposed, with no way to turn
  them off when a production deployment forgets to change anything;
- `PHISHGUARD_CORS_ORIGINS=*` was accepted silently (a wildcard origin with
  `allow_credentials=False` is not a credential leak, but it means every site can
  call the API from a browser);
- nothing failed fast, and nothing reported which configuration was actually
  active.

### F3 (Medium) — `repr(settings)` leaked the VirusTotal key value

`virustotal_api_key` is read from the environment and is not returned to clients,
but it appeared in the object's `repr()`. Any accidental `logger.info(settings)`
or exception that formats the settings object would print the key. Evidence:

```
repr leaks key? True
repr field present? True
```

### F4 (Medium) — documented-but-inert configuration variables

- `PHISHGUARD_LOG_LEVEL` was documented as controlling the log level but was
  never read by any code, and
- `PHISHGUARD_HISTORY_LIMIT` was declared in `config.py` but never used — the
  history route hard-coded `le=100`.

A variable that appears to work but does nothing is a deployment hazard: the
operator believes an override took effect.

### F5 (Medium) — PhishGuard's own `INFO` logs were invisible under uvicorn

uvicorn's default logging config attaches handlers only to `uvicorn` and
`uvicorn.access`; the root logger has none (verified from
`uvicorn.config.LOGGING_CONFIG` and by inspecting the live process). Records
emitted on the `phishguard` logger at `INFO` were therefore dropped by the
logging module's last-resort handler (`WARNING` or above). First live run of the
new startup summary demonstrated exactly this: the `WARNING` deployment lines
appeared, the `INFO` configuration line did not.

### F6 (Low) — no bounds on numeric configuration

`PHISHGUARD_MAX_REQUEST_BODY_BYTES`, `PHISHGUARD_RATE_LIMIT_WINDOW_SECONDS`,
`PHISHGUARD_HISTORY_LIMIT` and `PHISHGUARD_VIRUSTOTAL_TIMEOUT_SECONDS` accepted
any integer/float, including `0`, `-1` and absurdly large values.

### F7 (Low, documented not changed) — misleading "disabled" message

`app/providers/virustotal.py:164-175` always says *"no VIRUSTOTAL_API_KEY
configured"* when lookups are off, including when a key **is** set and only
`PHISHGUARD_VIRUSTOTAL_ENABLED=false`. It is user-facing API text outside this
milestone's scope, so it was left unchanged and is recorded here.

### F8 (Medium) — the test suite was not hermetic against host configuration

Running `pytest` in a shell that exports configuration changed the outcome: with
an ambient `VIRUSTOTAL_API_KEY` (and `PHISHGUARD_*` overrides) set, two existing
tests failed —

```
FAILED tests/test_api.py::test_analyze_without_vt_key_reports_disabled_intel
        AssertionError: assert 'invalid_key' == 'disabled'
FAILED tests/test_api.py::test_offline_mode_never_calls_network
        AssertionError: assert 'error' == 'disabled'
```

The statuses `invalid_key`/`error` show that the application genuinely **tried to
perform outbound VirusTotal lookups** with the host's key. So "the suite passes"
depended on the developer's environment, and a stray key could push the tests
into real network calls. (Reproduced before the fix; the suite was back to
240 passed once the ambient variables were removed.)

### Verified correct (no change needed)

| Area | Finding |
| --- | --- |
| CORS defaults | localhost-only, `allow_credentials=False`, `allow_methods=["GET","POST"]`, no wildcard; middleware ordering deliberate (Day 10). |
| Request body limit | 16 KiB default, enforced before parsing, 413 with a generic body. |
| In-process rate limiter | disabled by default, `/api/health` + `OPTIONS` exempt, `Retry-After` sent, limited to one process (documented as *not* a security boundary). No `X-Forwarded-For` trust anywhere. |
| SQLite path | relative settings already resolved against `backend/`, so the location is CWD-independent; verified by a new test. |
| SQLite writes | all statements parameterized; initialization is `CREATE TABLE IF NOT EXISTS` + additive `ALTER TABLE ADD COLUMN`; double `init_db()` is idempotent and never destructive. |
| Frontend API base URL | read from `VITE_API_BASE_URL`, injected at build time; an **empty** value yields same-origin relative `/api/...` requests (verified against the built bundle). |
| `/api/history?limit=` | `ge=1, le=100` validated by FastAPI; unknown ids → 404. |

## 3. Changes made

### 3.1 `backend/app/config.py` (modified)

- **`env_file` anchored to the backend directory** (`_BACKEND_DIR / ".env"`,
  absolute) so the operator's file is always the one used, whatever the CWD.
- **New `environment` setting** (`PHISHGUARD_ENVIRONMENT`, `development` by
  default) and **`docs_enabled`** (`PHISHGUARD_DOCS_ENABLED`, auto by default):
  in production the interactive docs are disabled unless explicitly re-enabled.
- **Fail-fast production validation**: a `model_validator` rejects a `*` entry in
  `PHISHGUARD_CORS_ORIGINS` when `environment=production` (error text contains no
  config values other than the origin policy).
- **Secret hygiene**: `virustotal_api_key` is `Field(..., repr=False)`, so it can
  no longer appear in `repr(settings)`. A new `startup_summary()` returns a
  non-secret snapshot (the key only as the boolean `virustotal_key_configured`),
  and `deployment_warnings()` returns non-fatal production concerns.
- **Value validation**: bounds for `history_limit` (1..1000),
  `max_request_body_bytes` (1 KiB..10 MiB), `rate_limit_requests` (>=1),
  `rate_limit_window_seconds` (>=1), `virustotal_timeout_seconds` (0..300), and a
  `log_level` validator that normalises case and rejects values `logging`/uvicorn
  would not honour (the offending value is not echoed, in case a variable was
  mis-set with something sensitive).
- **`resolved_database_path`**: single source of truth for the DB file location.

### 3.2 `backend/app/main.py` (modified)

- Settings are read **before** the app is constructed; `docs_url`, `redoc_url`
  and `openapi_url` are `None` when docs are disabled, so the routes are not
  registered at all (404).
- The lifespan now applies `log_level` to the `phishguard` logger, installs a
  fallback root handler **only when the root logger has none** (fixing F5; it
  never double-logs or overrides uvicorn's or a deployment's own logging), logs
  the non-secret startup summary, and logs each deployment warning.
- `GET /api/history` now takes its upper bound from `_settings.history_limit`
  (default 100, so the documented `?limit=1..100` contract is unchanged) instead
  of a hard-coded literal.

### 3.3 `backend/app/database.py` (modified)

- `_database_file()` delegates to `Settings.resolved_database_path`, removing a
  duplicated path-resolution rule (behavior identical: relative → `backend/`).

### 3.4 `backend/.env.example` (modified)

Documents `PHISHGUARD_ENVIRONMENT`, `PHISHGUARD_DOCS_ENABLED`,
`PHISHGUARD_HISTORY_LIMIT`, the corrected `PHISHGUARD_LOG_LEVEL` description, and
a "production notes" block (TLS at the proxy, proxy body cap + shared rate limit,
`--proxy-headers`/`--forwarded-allow-ips` only with a trusted proxy, no
`X-Forwarded-For` trust, persistent volume for the DB). No secret values.

### 3.5 `backend/tests/test_config.py` (new, 30 tests)

Defaults are dev-safe; `.env` is anchored to `backend/` and a CWD `.env` is
ignored; relative and absolute DB paths; production disables docs and can be
overridden; wildcard CORS rejected in production but allowed in development;
production deployment warnings; the key never appears in `repr()` or the startup
summary; log-level normalisation/validation; numeric bounds; docs served in
development and 404 in production; wildcard CORS prevents production startup; the
configured history limit is enforced; the startup summary is actually emitted and
contains no secret; the configured log level is applied.

### 3.6 `backend/tests/test_security.py` (+2 tests)

`test_configured_history_limit_is_enforced` (a configured cap of 1 → `?limit=5`
is 422) and `test_history_limit_default_keeps_documented_cap` (`100` → 200,
`101` → 422).

### 3.7 `backend/tests/test_database.py` (+1 test)

`test_resolved_database_path_matches_configured_file` pins the startup summary's
DB path to the file `init_db()`/`save_scan()` actually use.

### 3.8 `frontend/.env.example` and `README.md` (modified)

Frontend: documented the development value, the production value, and the
same-origin (empty/relative) option. README: new environment-variable rows, the
`VITE_API_BASE_URL` production guidance, the docs-disabled-in-production note,
the history-limit cap, and a corrected "Known limitations" entry (rate limiting
now exists but is opt-in and process-scoped).

### 3.9 `backend/tests/conftest.py` (new)

An autouse fixture removes host-supplied `PHISHGUARD_*` / `VIRUSTOTAL_API_KEY`
variables before every test, so results no longer depend on the developer's shell
and tests cannot be pushed into outbound lookups by an ambient key. Tests that
need these variables still set them explicitly with `monkeypatch.setenv`.

### 3.10 `backend/eval/DAY11_REPORT.md` (new)

This report. No previous day report was modified.

### Deliberately not changed

No authentication scaffolding (no user/role model exists, and nothing in this
milestone's findings justifies inventing one), no new dependency, no scoring
thresholds, no response-shape changes, no SQLite migrations/WAL/pragma tuning,
no trusted-proxy header parsing (a wrong implementation is worse than none), and
no dataset acquisition (still blocked).

## 4. Recommended reverse proxy / TLS setup (documentation)

1. Terminate TLS at the proxy (nginx/Caddy/cloud LB) and only forward HTTP to
   uvicorn on the loopback interface.
2. Enforce a request-body cap at the proxy (`client_max_body_size`) equal to or
   smaller than `PHISHGUARD_MAX_REQUEST_BODY_BYTES`.
3. Enforce the shared rate limit at the proxy/gateway. The built-in limiter is
   **per process**: with `uvicorn --workers N` each worker gets its own budget,
   so N workers allow up to N× the configured rate. It is abuse mitigation, not
   a security boundary.
4. Run uvicorn with `--proxy-headers --forwarded-allow-ips <proxy IP>` **only**
   if the proxy is trusted and strips inbound `X-Forwarded-*`. Never key rate
   limiting on `X-Forwarded-For` (PhishGuard does not).
5. Set `PHISHGUARD_ENVIRONMENT=production` and explicit
   `PHISHGUARD_CORS_ORIGINS` (wildcards are rejected). `/docs`, `/redoc` and
   `/openapi.json` are then not registered; if they must exist, restrict them at
   the proxy.
6. Keep `PHISHGUARD_DATABASE_PATH` on a persistent volume, include the file (and
   any `-wal`/`-shm` siblings) in backups, and remember SQLite is single-writer:
   run one application process against the file.
7. Add proxy-level request timeouts that exceed
   `PHISHGUARD_VIRUSTOTAL_TIMEOUT_SECONDS`, since a VirusTotal lookup runs
   synchronously inside `POST /api/analyze`.
8. `/api/health` is unauthenticated and runs `COUNT(*)`; point liveness probes at
   it from the proxy/platform, not from the public internet.

## 5. Verification actually performed

### 5.1 Backend suite (canonical environment)

```
cd backend
.\.venv\Scripts\python.exe -m pytest
=> 240 passed, 1 warning in 3.22s
```

Re-run from a deliberately hostile shell (ambient `VIRUSTOTAL_API_KEY`,
`PHISHGUARD_LOG_LEVEL=debug`, `PHISHGUARD_CORS_ORIGINS=*`,
`PHISHGUARD_ENVIRONMENT=production`):

```
=> 240 passed, 1 warning in 3.31s        (identical, thanks to tests/conftest.py)
```

The single warning is the pre-existing `StarletteDeprecationWarning: Using
httpx with starlette.testclient is deprecated; install httpx2 instead`
(`fastapi/testclient.py`). No new warning was introduced. Python 3.12.10 in
`backend/.venv`. Per file: analyzer 124, virustotal 21, api 20, config 30 (new),
dataset_import 23, security 14, eval 3, database 3, thresholds 2.

### 5.2 Frontend production build

```
cd frontend
npm run build
=> tsc -b && vite build
   35 modules transformed
   dist/assets/index-*.css   29.77 kB │ gzip:  5.92 kB
   dist/assets/index-*.js   278.50 kB │ gzip: 87.59 kB
   built in 247ms
```

Base-URL configurability was verified by inspecting the emitted bundle:

| Build | Result |
| --- | --- |
| default (no `VITE_API_BASE_URL`) | bundle contains `localhost:8000` |
| `VITE_API_BASE_URL=https://api.phisguard.example` | bundle contains that URL, **not** `localhost:8000` |
| `VITE_API_BASE_URL=` (explicitly empty) | no absolute host, relative `/api/analyze` retained |

(The empty case must be passed as a genuinely empty environment variable; in
PowerShell, `$env:X = ""` deletes the variable instead, which is why this was
checked with an explicit child-process environment.)

### 5.3 Live end-to-end checks (real uvicorn, 4 phases, 31/31 passed)

Run against `uvicorn app.main:app` on a loopback port with a temporary database,
`PHISHGUARD_VIRUSTOTAL_ENABLED=false` and **no** outbound network activity. URLs
used were the project's own local examples.

| Phase | Checks |
| --- | --- |
| A `development` | health 200; legitimate URL → `Low` (0); phishing-shaped URL → `Critical` (80); invalid input → 400; empty input → 422; oversized body (40 kB) → 413; history list 200 (total 2); history detail 200; unknown id → 404; `?limit=101` → 422; `?limit=5` → 200; `/docs` 200; `/openapi.json` 200; `x-content-type-options: nosniff`; threat intel `disabled` (no external call); startup summary logged; API key absent from the log; `virustotal_key_configured: True` reported as a boolean only. |
| B limiter on (3/60s) | health exempt; calls 1-3 → 200, call 4 → 429; 429 carries `Retry-After: 60` and a generic body; health still 200 while limited. |
| C `production` | `/docs`, `/redoc`, `/openapi.json` → 404; health 200; analyze 200; deployment warnings logged; API key absent from the log. |
| D `production` + `CORS=*` | process exits non-zero (1), log contains the wildcard error, nothing is left listening. |

Secret handling was checked explicitly: a dummy key value was set in the process
environment for every phase, and a scan of all four server logs found **zero**
occurrences of it. The startup line looks like (paths/temp DB shown):

```
INFO: phishguard: PhishGuard configuration: {'environment': 'development', 'database_path':
'C:\\...\\dev.db', 'cors_origins': ['http://localhost:5173', 'http://127.0.0.1:5173'],
'log_level': 'info', 'history_limit': 100, 'api_docs_enabled': True,
'max_request_body_bytes': 16384, 'rate_limit_enabled': False, 'rate_limit_requests': 60,
'rate_limit_window_seconds': 60, 'virustotal_enabled': False,
'virustotal_key_configured': True, 'virustotal_timeout_seconds': 10.0}
```

### 5.4 Browser-driven UI flow (built app + real backend)

The frontend was built with `VITE_API_BASE_URL=http://127.0.0.1:8029`, served
with `vite preview` on `localhost:4179`, and the backend started with
`PHISHGUARD_CORS_ORIGINS=http://localhost:4179`. Observed in the browser:

- `http://paypal.com.secure-login.evil.net/verify` → result view **Critical,
  80/100**, host, registered domain (`evil.net`) and 4 findings;
- `https://www.example.com/login` → **Low**, 1 finding, threat-intelligence panel
  reporting lookups disabled (offline heuristics only);
- "RECENT SCANS" listed the stored scan, and following it opened `/result/1`
  (the history detail route);
- backend access log for that session:
  `OPTIONS /api/history?limit=15 200`, `POST /api/analyze 200`,
  `GET /api/history/1 200`, `GET /api/history?limit=15 200`,
  `POST /api/analyze 200`, `GET /api/history/2 200` — i.e. health, analyze and
  history all exercised through the UI, not just through the API.

Screenshots could not be captured (the browser window was not visible to the
screenshot API), so this evidence is DOM snapshots plus server access logs rather
than images. Both local servers were stopped afterwards and the ports confirmed
free; the frontend `dist/` was rebuilt with default settings.

### 5.5 Behavior of the changed configuration

- `PHISHGUARD_CORS_ORIGINS=*` + `PHISHGUARD_ENVIRONMENT=production` → startup
  aborts (exit code 1) with a wildcard error; no port is opened.
- `PHISHGUARD_ENVIRONMENT=production` → `/docs`, `/redoc`, `/openapi.json` return
  404 while the API keeps working.
- `PHISHGUARD_HISTORY_LIMIT=1` → `?limit=1` 200, `?limit=5` 422 (wired up).
- `PHISHGUARD_LOG_LEVEL=warning` → applied to the `phishguard` logger.
- `PHISHGUARD_LOG_LEVEL=verbose` → rejected at load with a clear error.
- Analyzer bands re-read after the change: `_classify` still returns
  `Critical >=75`, `High >=50`, `Medium >=25`, else `Low`.

## 6. Operational limits that were **not** fixed in this milestone

1. **No authentication on any endpoint.** `/api/history` exposes the URLs users
   have analyzed. Adding auth is a product decision (accounts, tokens, ownership)
   and was explicitly out of scope; it remains the largest gap.
2. **The rate limiter is per process.** Any multi-worker or multi-replica
   deployment multiplies the budget. Only a proxy/gateway limit is effective.
3. **SQLite is a single-writer store.** No WAL mode, no explicit busy timeout
   tuning, no connection pool; write contention surfaces as "database is locked",
   which is mapped to a generic 503. Moving to a server database is a bigger
   decision than this milestone.
4. **Unbounded history growth.** Every analysis inserts a row forever; no
   retention, rotation or archival. Deleting scan history is destructive and was
   deliberately not implemented without an explicit retention decision.
5. **No backup/restore mechanism** for the database file.
6. **`/api/health` performs `COUNT(*)`** on every probe.
7. **No application-level request timeout or concurrency cap.** A slow VirusTotal
   lookup occupies the worker for up to `virustotal_timeout_seconds`.
8. **No TLS in the application.** It must be terminated at a proxy.
9. **Trusted-proxy headers are not implemented.** If a proxy is added, uvicorn's
   `--proxy-headers` must be configured *and* the limiter revisited; PhishGuard
   itself never trusts `X-Forwarded-For`.

## 7. Remaining risks and recommended next milestone

The Day 11 changes remove the two ways this deployment could silently run with
the wrong configuration (F1, F2), stop the API key from appearing in logs (F3),
remove inert/misleading variables (F4, F5) and make bad values fail fast (F6).
They do not make the service production-secure: the service still has no
authentication, SQLite is still a single-writer file database, history is still
unbounded, and nothing was load-, fuzz- or penetration-tested.

Recommended next milestone: **Day 12 — deployment artifacts and data lifecycle.**
Concretely: (a) a documented retention/rotation + backup design for
`phisguard.db` (with an explicit decision before any deletion), (b) a decision on
authentication for `/api/history`, and (c) a reproducible deployment artifact
(nginx/Caddy sample with TLS, body cap, shared rate limit, and a systemd/Compose
unit running a single worker against a persistent volume) so the proxy
recommendations in §4 become executable rather than prose.

Still blocked from Day 9 and unchanged: real-data evaluation needs
`backend/eval/data/phishtank-online-valid.csv` and `tranco-top-1m.csv` placed by
hand (see `DAY9_REPORT.md` §5); no dataset was downloaded, resolved or submitted.
