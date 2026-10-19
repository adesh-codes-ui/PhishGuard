# Day 15: Current-State Audit, Revalidation and Two Verified Fixes

**Date:** 2026-10-19 (local session date on the machine where this ran)
**Environment:** Windows 11/10, PowerShell, Python 3.12.10 venv at `backend/.venv`,
SQLite 3.49.1 (Python stdlib driver), Node.js 24 / npm, Vite 8.3.4, TypeScript 6.0.
**Scope:** establish the *actual* state of the repository, re-run all validation,
audit for remaining gaps, fix only clearly verified defects, revalidate, report.

> **No Git repository exists in this workspace** (`git rev-parse --is-inside-work-tree`
> → not a repo). **No Git diff was produced or reviewed.** Every "change" listed
> below was identified by re-reading the affected files after editing them.

---

## 1. Initial repository state (verified, not assumed)

### 1.1 What exists on disk

`backend/eval/` was listed before anything was done. Present:

```
DAY6_REPORT.md  DAY7_REPORT.md  DAY8_REPORT.md  DAY9_REPORT.md
DAY10_REPORT.md DAY11_REPORT.md DAY12_REPORT.md
EVALUATION_REPORT.md  DATASETS.md  README.md
analyze_thresholds.py  evaluator.py  fixtures.jsonl  import_dataset.py
```

* **`DAY13_REPORT.md` does NOT exist.** **`DAY14_REPORT.md` does NOT exist.**
  Confirmed by directory listing *and* by a content search across the whole
  repository (`grep` for `DAY13|DAY14` → no matches). No report was overwritten.
  Session summaries that refer to a Day 13/14 report are therefore **not
  corroborated by the repository** and are treated here as unverifiable history.
* Day-15 artifacts to be created: `DAY15_REPORT.md` (this file, new).

### 1.2 Files inspected

| Area | Files read or listed |
| --- | --- |
| Root | `README.md` (all 315 lines), `.gitignore`, root `package-lock.json` |
| Backend app | `app/main.py`, `app/analyzer.py`, `app/config.py`, `app/database.py`, `app/schemas.py`, `app/security.py`, `app/providers/virustotal.py` (grep) |
| Backend tests | `tests/` directory listing (11 test modules + `conftest.py`), `test_api.py`, `test_analyzer.py`, `test_deploy_artifacts.py`, `test_security.py` (targeted), `pytest.ini`, `requirements.txt` |
| Backend ops | `ops/db_lifecycle.py` (CLI parser + delete-path search), run live (§3.4) |
| Backend eval | directory listing, `DAY6_REPORT.md`, `DAY10_REPORT.md` (style/precedent) |
| Frontend | `src/api/client.ts`, `src/App.tsx`, `src/pages/Dashboard.tsx`, `src/pages/ResultPage.tsx`, `src/components/{UrlForm,HistoryList,RiskBadge,RiskGauge,Spinner,FindingList,ThreatIntelPanel}.tsx`, `src/lib/risk.ts`, `index.html`, `package.json`, `vite.config.ts`, `.env.example` |
| Deploy | `deploy/` listing, `deploy/phisguard.service`, `deploy/phishguard.env.example`, `deploy/nginx-phisguard.conf.example`, `deploy/README.md`, `deploy/Caddyfile.example` (present) |
| Env/secrets | `backend/.env.example`, `frontend/.env.example`, secret-pattern grep over the repo (no matches), no `backend/.env` present |

### 1.3 Baseline **before** any change (both commands run today)

```
cd backend
.\.venv\Scripts\python.exe -m pytest -q
    → ======================= 320 passed, 1 warning in 3.32s ========================
      exit code 0
      warning = StarletteDeprecationWarning: Using `httpx` with `starlette.testclient`
                is deprecated; install `httpx2` instead.   (from installed fastapi,
                not from project code)

cd frontend
npm run build
    → tsc -b && vite build ; vite 8.3.4 ; 35 modules transformed
      dist/index.html                   0.65 kB │ gzip:  0.39 kB
      dist/assets/index-DQmeeZmu.css   29.77 kB │ gzip:  5.92 kB
      dist/assets/index-CcigVZvh.js   278.50 kB │ gzip: 87.59 kB
      ✓ built in 1.07s   exit code 0

cd frontend
npm run lint
    → 2 warnings (pre-existing: react/set-state-in-effect in Dashboard.tsx:45 and
      ResultPage.tsx:46)   exit code 0
```

**No earlier test/build number was reused.** The counts above were produced by
re-running both commands at the start of this session. Note they differ from
figures quoted in older session summaries (e.g. "71 modules / 69 kB"); the
numbers in this file are the ones actually observed on 2026-10-19.

---

## 2. Findings, ranked

Severity = impact if the application is deployed as-is. **V** = verified defect
(reproduced with a command or a browser), **R** = recommendation, **U** = concern
not proven on this machine.

### CRITICAL

*None verified.*

### HIGH

| # | Finding | Type | Status |
| --- | --- | --- | --- |
| H-1 | **`GET /api/history` and `GET /api/history/{id}` are unauthenticated** and return every URL anyone has analyzed on the instance. Confirmed by reading `app/main.py` (no auth dependency, no credential check) and by calling both routes with no credentials (200). | V (behaviour) / product decision | **Not changed.** Adding auth is an explicit unresolved product decision; the brief forbids auth or breaking API changes without explaining impact and tests. `README.md`, `deploy/README.md` and the nginx template already document it and offer a proxy-level `auth_basic` option. |

### MEDIUM

| # | Finding | Type | Status |
| --- | --- | --- | --- |
| M-1 | **Schemeless `host:port` fallback accepted non-HTTP schemes whose opaque part is numeric.** `tel:12345`, `data:1234`, `javascript:1`, `file:1`, `sms:999` were rewritten to `http://tel:12345/` … and analysed (score 25, *Medium*) instead of being refused. This contradicts `README.md` ("`javascript:`, `data:`, `file:` … are rejected") and the existing test that rejects `tel:+123456` — the same scheme was accepted or rejected depending only on whether a `+` followed the digits. | **V — verified defect** | **Fixed** (§3.1) + 11 regression tests |
| M-2 | **A mis-routed `VITE_API_BASE_URL` surfaced a raw `SyntaxError`.** When the API base points at a path prefix (the exact misconfiguration `frontend/.env.example` warns about), the SPA fallback answers `/api/...` with `200 text/html` (`index.html`). `client.ts` called `response.json()` on a 2xx response without a guard, so the user banner showed `SyntaxError: Unexpected token '<'`. | **V — verified defect** | **Fixed** (§3.2), verified in a real browser |
| M-3 | **The frontend has no automated tests at all.** `package.json` defines `dev`, `build`, `lint`, `preview` — no `test` script; no test runner is installed; no `*.test.ts(x)` file exists. Frontend correctness is currently established only by `tsc -b`, `oxlint`, and manual/browser checks (§3.5). | V (gap) | **Not changed** — closing it needs a new dependency (vitest/jsdom/Testing Library), which the brief disallows as "unnecessary". Recommended as the next milestone. |
| M-4 | **Real-data evaluation is still blocked.** `backend/eval/data/` is absent (it is `.gitignore`d and was never created), so no external PhishTank/URLhaus-style dataset is present. Accuracy figures in older reports are **synthetic-fixture-only** and are not independently verifiable here. | V (status) | Unchanged; see §7 |
| M-5 | **The in-process rate limiter is off by default and is process-local**, so `uvicorn --workers N` multiplies the effective budget by N. Documented in `config.py`, `.env.example`, `README.md` and `deploy/nginx-phisguard.conf.example` (which ships `limit_req`). | R | Behaviour live-verified (§3.3); enforcement belongs at the proxy |

### LOW

| # | Finding | Type | Status |
| --- | --- | --- | --- |
| L-1 | **`HistoryList` error panel had no `role="alert"`** while the Dashboard and ResultPage error banners do (confirmed by `grep role=`: `Dashboard.tsx:82`, `ResultPage.tsx:81`, absent in `HistoryList.tsx`). Screen readers therefore did not announce a failed history load. | **V — verified defect** | **Fixed** (§3.3) |
| L-2 | **`README.md` project-structure block was stale**: it listed 3 test modules where 11 exist, and omitted `backend/eval/` entirely. | **V — verified drift** | **Fixed** (§3.4) |
| L-3 | **Stray root `package-lock.json`** containing `"packages": {}` with **no** root `package.json`. Harmless but misleading. | V | **Not changed** — with no Git history it cannot be proven untracked, so it was left in place and is flagged for the owner. |
| L-4 | **`oxlint` emits 2 pre-existing warnings** (`react(set-state-in-effect)`, `Dashboard.tsx:45`, `ResultPage.tsx:46`). Lint still exits 0. | V | Not changed — fixing means restructuring `useEffect`/`useState` in working code (churn risk, no functional gain today) |
| L-5 | **Deployment templates remain unvalidated**: no `nginx`, `caddy`, `systemd-analyze`, `docker`/`podman`, `openssl` binary and no WSL on this machine, so `nginx -t` and friends could not be run. The templates say so themselves. | U / environmental | Unchanged; documented as a limitation |
| L-6 | **Retention period is still undefined**; `ops/db_lifecycle.py` deliberately contains no delete path. Verified live: `retention-plan --keep 1` returned `"deletion_implemented": false`. | V (status) / product decision | Unchanged |
| L-7 | **Backups contain analyzed URLs in clear text** and default to `<database dir>/backups`. `README.md` already tells operators to store them encrypted. | R | Unchanged |
| L-8 | Minor a11y nit: the `RiskGauge` decorative `<svg>` is not marked `aria-hidden`; the score is exposed as real text next to it, so impact is negligible. | R | Unchanged |

**Explicitly *not* found (checked, no defect):** hardcoded secrets (pattern grep → 0
matches), `.env` files present (only `.env.example`), SQL string interpolation
(all queries parameterized), `dangerouslySetInnerHTML` / `innerHTML` (absent),
`POST` to any external service (VirusTotal provider issues only
`GET /urls/{base64url(sha256(url))}`; `httpx.Client` is never constructed when no
key is configured), rate-limit health/OPTIONS exemption mismatch between docs and
code (`.env.example` and `security.py` agree), and double-`/api/` base-URL handling
(documented in `frontend/.env.example`).

---

## 3. Actual changes made

Four edits, all small, none touching scoring thresholds, weights, bands
(Low 0–24 / Medium 25–49 / High 50–74 / Critical 75–100), the success response
contract, `requirements.txt`, or any endpoint signature.

### 3.1 `backend/app/analyzer.py` — reject non-HTTP schemes hidden by the `host:port` fallback (fixes M-1)

Added `_looks_like_schemeless_host()` and consulted it in the no-scheme branch of
`normalize_url()`. The bare-`host:port` reading is now allowed only when the
token before the colon looks like a host: a **dotted** name (incl. IPv4),
**`localhost`**, or an **IP literal**. Anything else is treated as a URI scheme
and rejected as unsupported.

Verified behaviour change (probe script, run before and after):

| Input | Before | After |
| --- | --- | --- |
| `tel:12345` | accepted → `http://tel:12345/`, score 25 Medium | **400** `Unsupported URL scheme 'tel'…` |
| `data:1234` | accepted → `http://data:1234/` | **400** |
| `javascript:1` | accepted → `http://javascript:1/` | **400** |
| `file:1`, `sms:999` | accepted | **400** |
| `example.com:8080/path` | accepted | accepted (unchanged) |
| `example.com:8080/path?u=http://x` | accepted | accepted (unchanged) |
| `x.test:8080` | accepted | accepted (unchanged) |
| `localhost:8000/api/health` | accepted | accepted (unchanged) |
| `tel:+123456`, `javascript:alert(1)`, `ftp://…`, `mailto:…` | rejected | rejected (unchanged) |
| 23 other probe URLs (IDN, punycode, IPv6, obfuscated IPs, ports, userinfo, casing, whitespace, oversized port) | unchanged | unchanged |

**Documented trade-off:** a *single-label* intranet host with a port
(`myserver:8080`) is now refused too, because it is syntactically
indistinguishable from a `myserver:...` URI. The workaround — write the scheme
out, `http://myserver:8080` — is covered by a test and explained in the helper's
docstring. This is deliberately fail-closed.

### 3.2 `frontend/src/api/client.ts` — guard the 2xx response parse (fixes M-2)

`response.json()` on a successful response is now wrapped; a non-JSON 2xx body
throws `ApiError('The API returned a response that was not JSON. Check
VITE_API_BASE_URL.', status)` instead of an unhandled `SyntaxError`. Error
bodies on non-2xx responses were already parsed defensively and are unchanged.

### 3.3 `frontend/src/components/HistoryList.tsx` — announce history errors (fixes L-1)

Added `role="alert"` to the existing error panel div, matching
`Dashboard.tsx:82` and `ResultPage.tsx:81`. Text, classes and behaviour
otherwise untouched.

### 3.4 `README.md` — correct the project-structure block (fixes L-2)

Replaced the 3-file `tests/` listing with an accurate description of the 11 test
modules and added the `eval/` entry. No other README content changed.

### Regression tests added (11 new, all in the existing suites)

`backend/tests/test_analyzer.py`:

* `test_numeric_opaque_parts_of_non_http_schemes_are_rejected` — parametrized over
  `tel:12345`, `data:1234`, `javascript:1`, `file:1`, `sms:999` (5 tests).
* `test_schemeless_host_with_port_is_still_accepted` — parametrized over
  `example.com:8080/path`, `example.com:8080/path?u=http://x`, `x.test:8080`,
  `localhost:8000/api/health` (4 tests). **Guards against regressing the
  documented bare-host feature.**
* `test_single_label_intranet_host_may_need_an_explicit_scheme` — pins the
  trade-off in both directions (1 test).

`backend/tests/test_api.py`:

* `test_analyze_rejects_numeric_opaque_schemes_and_keeps_working` — HTTP-level:
  three rejections return 400 with a `"scheme"` message, nothing is persisted
  (`scans_stored == 0`), and a subsequent valid analysis still returns 200 (1 test).

No thresholds, weights, bands, datasets or metrics were modified. No new
dependency was installed. No URL was submitted to any external service.

---

## 4. Backend test results — before and after

| When | Command | Result | Exit |
| --- | --- | --- | --- |
| Start of Day 15 (baseline) | `cd backend; .\.venv\Scripts\python.exe -m pytest -q` | **320 passed, 1 warning in 3.32s** | 0 |
| After the analyzer fix, before new tests | `.\.venv\Scripts\python.exe -m pytest -q` | **320 passed, 1 warning in 2.42s** (no regressions from the fix) | 0 |
| After adding the 11 regression tests (final) | `.\.venv\Scripts\python.exe -m pytest -q` | **331 passed, 1 warning in 2.47s** | 0 |

The single warning is unchanged in kind: `StarletteDeprecationWarning: Using
httpx with starlette.testclient is deprecated; install httpx2 instead`, raised
from `.venv\Lib\site-packages\fastapi\testclient.py:1` — i.e. from the installed
FastAPI, not from project code. It was present before and after; no test failed.

## 5. Frontend build result

| When | Command | Result | Exit |
| --- | --- | --- | --- |
| Baseline | `cd frontend; npm run build` | 35 modules; `index.html` 0.65 kB, CSS 29.77 kB (gzip 5.92), JS **278.50 kB** (gzip 87.59); built in 1.07s | 0 |
| After changes | `npm run build` | 35 modules; JS **278.62 kB** (gzip 87.64); built in 228ms | 0 |
| Final rebuild (temp env file removed, defaults restored) | `npm run build` | 35 modules; JS 278.62 kB (gzip 87.64), `dist/assets/index-WZtB1Vpa.js` | 0 |
| Lint after changes | `npm run lint` | 2 pre-existing warnings, unchanged | 0 |

`npm` with the existing `package-lock.json` was used; **no package was
installed, added or upgraded** during Day 15.

---

## 6. Integration checks actually performed

Every item below was executed on 2026-10-19. Nothing in this section is
inferred from a previous session.

### 6.1 HTTP checks against a real `uvicorn` process

Started with `.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port …`
against a throwaway `PHISHGUARD_DATABASE_PATH` under
`C:\Users\Akskc\AppData\Local\Temp\opencode\`.

| Check | Result |
| --- | --- |
| `GET /api/health` | `{"status":"ok","version":"0.1.0","scans_stored":0}` |
| `POST /api/analyze` valid phishing URL | 200, `Critical 80`, host `paypal.com.secure-login.evil.net`, 4 findings, `registrable_domain=evil.net`, `threat_intel.status=disabled` |
| `POST /api/analyze` `javascript:alert(1)` | 400 |
| `POST /api/analyze` `tel:12345` (after fix) | 400 (was 200 before the fix) |
| `GET /api/history?limit=5` | 200, `total=1`, 1 item |
| `GET /api/history/{id}` | 200 with findings |
| `GET /api/history/999999` | 404 |

### 6.2 Rate limiting and body-size limits (live, dedicated instances)

| Scenario | Result |
| --- | --- |
| `PHISHGUARD_RATE_LIMIT_ENABLED=true`, `…_REQUESTS=5` | requests 1–5 → **200**; 6–8 → **429** `{"detail":"Rate limit exceeded. Try again later."}` with `Retry-After: 60` |
| Same instance, after exhaustion: `GET /api/health` | **200** (exempt confirmed *after* the budget was spent) |
| Same instance, after exhaustion: `OPTIONS` preflight | **200** (exempt) |
| Same instance, after exhaustion: unknown path `/api/nope` | **429** (non-`/api`-restricted counting confirmed) |
| `PHISHGUARD_MAX_REQUEST_BODY_BYTES=1024`, rate limiting off, 2 KiB body | **413**; a subsequent valid request → 200 |

### 6.3 Database lifecycle CLI (live, throwaway database)

Database created with 3 rows, then:

| Command | Exit | Observed |
| --- | --- | --- |
| `db_lifecycle.py info --database …` | 0 | JSON description, columns listed |
| `… backup --label day15 --output-dir …` | 0 | backup + `.db.json` manifest, `sha256`, `integrity_check: "ok"`, `row_count: 3`, method `sqlite3 online backup API` |
| `… verify --backup …` | 0 | `file_exists`, `file_non_empty`, … all `ok` |
| `… restore --backup … --target …` | 0 | `restored: true`, `verified_against_backup: true`, `replaced_file: null` |
| `… info --database <restored>` | 0 | restored database readable |
| `… retention-plan` (no policy) | **1** | `error: specify --keep and/or --older-than-days` |
| `… retention-plan --keep 1` | 0 | `would_keep: 1`, `would_remove: 2`, **`"deletion_implemented": false`** |

### 6.4 Browser end-to-end (real Chromium, `vite dev` on 5173 + backend on 8000)

* Page loaded; **`GET /api/history?limit=15` → 200** and CORS **`OPTIONS` → 200**,
  requested against **`http://localhost:8000`** — i.e. the frontend uses the
  correct backend URL by default (`import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'`).
* Submitted `https://www.example.com/login` through the real form → navigated to
  `/result/1`, rendered **Low 15/100**, "WHY THIS SCORE (1 FINDING)", threat
  intel panel ("Not configured … never changes the heuristic score").
* Dashboard "RECENT SCANS" then listed the scan with the right label/score/time.
* `POST /api/analyze` with `javascript:alert(1)` → UI alert
  `⚠ Unsupported URL scheme 'javascript'. Only http and https are allowed.`
* `POST /api/analyze` with `tel:12345` **after the fix** → UI alert
  `⚠ Unsupported URL scheme 'tel'. Only http and https are allowed.`
  (Before the fix the same input produced a *successful* result page — this is
  the M-1 defect observed end to end.)
* `/result/999999` → 404 from the API, UI shows **"Scan not found … Back to
  dashboard"** (loading state first, then the error state).
* Console messages checked before and after: only the React DevTools notice and
  the deliberately provoked 400; **no uncaught errors, no CORS failures** in the
  happy path.

### 6.5 Frontend misconfiguration E2E (verifies fix 3.2)

Created a temporary `frontend/.env.production.local` containing
`VITE_API_BASE_URL=/api` (the misconfiguration `.env.example` warns about),
ran `npm run build` (exit 0) and `npm run preview`, then loaded the page:

* Network log: `GET http://localhost:4173/api/api/history?limit=15 → 200`,
  served as `text/html` (`<!doctype html>…` — the SPA fallback).
* **Observed UI text:** `Recent scans / Refresh / The API returned a response
  that was not JSON. Check VITE_API_BASE_URL.` with **no console errors**.
* The temporary env file was then **deleted** (`Test-Path` → `False`) and the
  project was rebuilt with default settings (exit 0). Only `.env.example`
  remains in `frontend/`.

### 6.6 Cleanup

Ports 8000, 5173, 4173 (and the ad-hoc 8123/8222/8223/8224) confirmed not
listening; all temporary databases, backups and probes live under
`C:\Users\Akskc\AppData\Local\Temp\opencode\`; no stray `.env*` files in the
repository.

### 6.7 Checks that were NOT performed (stated honestly)

* **No Git:** no repository → no diff produced or reviewed.
* **No deployment validation:** `nginx -t`, `caddy validate`,
  `systemd-analyze verify`, `docker`/`podman`, `openssl`, `sqlite3` CLI are all
  absent and WSL is not installed.
* **No real-data evaluation:** `backend/eval/data/` does not exist.
* **No fuzzing, load testing, or penetration testing.** This was a static review
  plus targeted execution, not a security assessment.
* **No automated frontend unit tests** (see M-3); frontend verification was
  `tsc -b`, `oxlint`, a production build, and the browser checks above.

---

## 7. Real-data evaluation status

**Still blocked — unchanged.** No external dataset is present, so no precision,
recall or accuracy number is reported for Day 15. Any such figure appearing in
Day 6–12 material derives from `backend/eval/fixtures.jsonl` / synthetic inputs
and is **synthetic-only, not generalizable, and not independently verifiable
from this repository**. The only quantitative claims made in *this* file are
test counts, build sizes, and HTTP status codes that were produced by the
commands quoted above.

## 8. Remaining risks

1. **Unauthenticated history (H-1)** — anyone who can reach the API can read every
   analyzed URL. Highest-impact open item; needs a product decision.
2. **No retention/deletion (L-6)** — the SQLite file grows without bound; backups
   accumulate analyzed URLs (L-7).
3. **No frontend test suite (M-3)** — a regression in the UI can only be caught by
   `tsc`, `oxlint`, or a human clicking through.
4. **Rate limiting is per-process and off by default (M-5)** — acceptable only
   behind the nginx/Caddy templates, which themselves are unvalidated here (L-5).
5. **Single-label `host:port` trade-off (§3.1)** — an operator pasting
   `myserver:8080` now gets a 400 until they write `http://`.
6. **VirusTotal lookups run synchronously inside `POST /api/analyze`** — a slow
   provider adds up to `PHISHGUARD_VIRUSTOTAL_TIMEOUT_SECONDS` (10 s default) to
   that request; mitigated only by the proxy's `proxy_read_timeout 30s`.

## 9. Deployment limitations (this machine)

No proxy, service manager, container runtime, TLS tooling or `sqlite3` CLI is
available, and WSL is not installed. `deploy/nginx-phisguard.conf.example`,
`deploy/Caddyfile.example`, `deploy/phisguard.service` and `deploy/phishguard.env.example`
were therefore **read for consistency only** and remain **unexecuted examples**.
Run `sudo nginx -t`, `caddy validate`, `systemd-analyze verify` and obtain a
certificate before relying on them. Consistency spot-checks that *were* done by
reading: systemd `ExecStart` uses `backend/.venv/bin/uvicorn` (matching the
documented venv), `StateDirectoryMode=0700` and `UMask=0077` are set, nginx
ships `client_max_body_size 16k` (= the app's 16384-byte default) plus
`limit_req_zone` at 60 r/m, and the certbot step precedes `nginx -t` in
`deploy/README.md`.

## 10. Recommended next milestone

**Milestone: a frontend test suite plus an end-to-end smoke test, then a real
dataset.**

1. Add a test runner for `frontend/` (vitest + jsdom + Testing Library) and cover
   `api/client.ts` error mapping (400 `detail`, 429, 0/offline, non-JSON 2xx —
   today only the last one is browser-verified) and the Dashboard/ResultPage
   loading and error states. *Requires adding a dev dependency — needs explicit
   approval.*
2. Make a product decision on **history authentication** (H-1) and on a
   **retention period** (L-6); both are documented and deliberately deferred.
3. Populate `backend/eval/data/` (gitignored) with a licensed URL dataset and run
   `evaluator.py` to replace synthetic-only figures with real ones — without
   touching thresholds until a held-out set exists (per Day 6's decision).
4. Validate the deployment templates on a real host (`nginx -t`,
   `systemd-analyze verify`), or mark them explicitly experimental in
   `deploy/README.md`.
5. Optional hardening: proxy-level `auth_basic` for `/api/history`, encrypted
   backup storage, `aria-hidden` on the gauge SVG, resolving the two
   `set-state-in-effect` lint warnings.

---

## 11. Traceability of every command quoted

| Purpose | Command | Exit |
| --- | --- | --- |
| Is this a Git repo? | `git rev-parse --is-inside-work-tree` | not a repo |
| Baseline tests | `cd backend; .\.venv\Scripts\python.exe -m pytest -q` | 0 (320 passed) |
| Baseline build | `cd frontend; npm run build` | 0 |
| Baseline lint | `cd frontend; npm run lint` | 0 (2 warnings) |
| Analyzer probe (before) | `.\.venv\Scripts\python.exe <temp>\probe_urls.py` | 0 |
| Regression probe (after) | `.\.venv\Scripts\python.exe <temp>\probe2.py` | 0 |
| Tests after analyzer fix | `.\.venv\Scripts\python.exe -m pytest -q` | 0 (320 passed) |
| Tests after new tests | `.\.venv\Scripts\python.exe -m pytest -q` | 0 (331 passed) |
| Build after changes | `npm run build` | 0 |
| Lint after changes | `npm run lint` | 0 (2 warnings) |
| Ops CLI (5 commands) | `python ops\db_lifecycle.py …` | 0,0,0,0,0 and 1 for policy-less `retention-plan` |
| Rate/body-limit instance | `uvicorn app.main:app --port 8222/8223/8224` + `Invoke-WebRequest` | 0 (per-request statuses in §6.2) |
| Misconfigured-base build/preview | `npm run build`, `npm run preview` with `VITE_API_BASE_URL=/api` | 0 |
| Final rebuild (defaults) | `npm run build` | 0 |

*Unverifiable historical results (explicitly labelled):* any Day 1–12 test count,
build size or evaluation metric quoted in older reports or in session summaries
was **not** reproduced during Day 15 and is **not** claimed here. The absence of
`DAY13_REPORT.md` and `DAY14_REPORT.md` means any Day-13/14 claims have **no
on-disk evidence** in this repository.
