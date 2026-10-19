# Day 20 — Repeatable end-to-end validation

**Date:** 2026-10-19
**Scope:** add the smallest reliable, repeatable end-to-end (E2E) check for the
local-only PhishGuard demo, covering the seam that the unit/component suites
cannot reach (real server processes, real HTTP, real SQLite persistence, CORS
over a socket). No public deployment, no production claim, no accuracy claim.

---

## 1. Scope and constraints honoured

This project is a **local-only demonstration**. Day 20 did **not**:

- configure or imply public/production deployment;
- add authentication, a user model, or change any API contract;
- change scoring thresholds or weights;
- add any runtime or dev dependency;
- contact VirusTotal or any external service;
- use the developer's real database (`backend/phisguard.db`) for testing;
- expose secrets, or claim phishing-detection accuracy or a security audit.

The recommendation (Phase 2) was **requested for approval and not answered**;
work proceeded with the recommended **no-install** option (below), because it
needs no dependency approval and does not alter the existing test suites.

---

## 2. Phase 1 — What existed, and what was missing

### 2.1 The only existing "end-to-end" checklist was manual prose

There was no E2E script, no `*.spec/*.e2e/*.cy` file, no `.ps1` helper, and no
CI configuration. The only E2E checklist was prose in
`backend/eval/DAY18_REPORT.md` §7 — a human-driven table of two browser
sessions.

### 2.2 What the existing suites already cover

| Suite | Environment | Covers | Does not start |
| --- | --- | --- | --- |
| `frontend/src/api/client.test.ts` (17) | Node | URL construction, error→`ApiError`, base URL | any server |
| `frontend/src/app-render.test.tsx` (8) | Node (`react-dom/server`) | route rendering, no-`fetch` purity of render | effects, submission |
| `frontend/src/app.integration.test.tsx` (10) | jsdom | dashboard load/empty/error+Retry, submit (trimmed body), result render, 404, 500+Retry, keyed remount — **`fetch` stubbed** | a real backend |
| `backend/tests/*` (331) | pytest `TestClient` (in-process ASGI) | analyzer, API contract, DB, config, eval, ops, thresholds; **CORS preflight allow/deny, 413, 429, security headers** | a real socket / uvicorn process |

Every one of these runs **in-process** (ASGI `TestClient` or a stubbed `fetch`).
None launches a server process or opens a socket.

### 2.3 The behaviours that needed running servers (the real gap)

uvicorn actually starting and binding loopback; readiness; real HTTP over a
socket; **SQLite persistence across separate processes**; the built frontend
being served with SPA route fallback; a **real browser's CORS enforcement**; and
API failure/recovery against a genuinely down/up backend.

### 2.4 Tooling and dependencies found

- Installed: Node **24.17.0** (global `fetch`), npm 11.13.0, Vitest **5.0.5**,
  jsdom **30.1.3**, Testing Library; backend venv with **uvicorn 0.54.0**,
  FastAPI 0.143.3; `frontend/dist/` was already built.
- **Not** installed: Playwright, Puppeteer, Cypress, happy-dom. No
  `vitest.config.*`.
- The harness also exposes agent-only browser tools (Chromium). They are useful
  for a one-off manual pass but are **not** runnable by a grader from the
  repository, so they cannot be the repeatable mechanism.

---

## 3. Phase 2 — Decision

| | Approach | New deps | Result-page DOM | Live seam | Complexity / risk |
| --- | --- | --- | --- | --- | --- |
| **A (chosen)** | Zero-dependency Node script boots real backend + built frontend on isolated loopback ports, drives the flow over HTTP | **none** | SPA shell + API data | **yes** | Low; isolated from Vitest's worker model |
| B | Dedicated jsdom Vitest file spawning the backend, driving the real `App` | none | **yes** | backend only | Medium; needs a Vitest config + in-worker process spawning (the known flake area) |
| C | Playwright real browser | **+`@playwright/test` + Chromium** | yes | yes | High; needs dependency approval |

**Chosen: Option A.** It is the simplest reliable way to automate exactly the
seam unit tests cannot reach, adds no dependencies, and needs no Vitest config
(so `npm test` is unchanged). Browser-only concerns (real CORS enforcement, the
DOM against a live backend) are covered by the existing jsdom suite plus the
manual real-browser pass in §7.

---

## 4. What was automated

A single, self-contained script: **`scripts/e2e-smoke.mjs`** (no dependencies —
Node built-ins plus the global `fetch`). It:

1. picks two free **loopback** ports and creates a **fresh temporary database**
   (`%TEMP%/phisguard-e2e-*/e2e.db`);
2. starts the **real backend** — the venv `python -m uvicorn app.main:app
   --host 127.0.0.1 --port <p>` — with `PHISHGUARD_DATABASE_PATH` pointed at the
   temp file and `VIRUSTOTAL_API_KEY` / ambient `PHISHGUARD_*` stripped;
3. starts the **real built frontend** — `vite preview --host 127.0.0.1` on
   `frontend/dist`;
4. **polls readiness** (bounded) instead of sleeping: `/api/health` returns
   `{"status":"ok"}` and the SPA shell contains `id="root"`;
5. asserts, in order:
   - a fresh isolated database starts empty (`scans_stored == 0`);
   - `POST /api/analyze` → 200, `Critical`, score ≥ 50 (real heuristics);
   - external threat intel is offline (`threat_intel.status == "disabled"`);
   - the isolated SQLite file exists on disk (persistence);
   - `GET /api/history/{id}` returns the full result payload with findings;
   - `GET /api/history` lists the stored scan;
   - an unknown id (`999999`) returns **404**;
   - **CORS** `OPTIONS` over a real socket: allowed origin echoes
     `Access-Control-Allow-Origin`, unknown origin does not;
   - the frontend serves the SPA shell for `/`, `/result/1`, `/result/999999`;
   - **failure/recovery**: once the backend is stopped requests fail, and after
     restarting it the history still contains the scan (SQLite persistence
     **across processes**);
6. **always tears down** — kills the child processes (SIGTERM, then
   `taskkill /T /F` on Windows) and deletes the temp directory — on success, on
   failure, and on `SIGINT`/`SIGTERM`.

### 4.1 Files changed (Day 20)

| File | Change |
| --- | --- |
| `scripts/e2e-smoke.mjs` | **new** — the E2E smoke test |
| `frontend/package.json` | added `"test:e2e": "node ../scripts/e2e-smoke.mjs"` (script entry only; **no dependency change**) |
| `backend/eval/DAY20_REPORT.md` | **new** — this report |

No source, test, config, or dependency file was modified. `backend/phisguard.db`
and `frontend/dist/` were not part of the change set.

---

## 5. How to run it

From `frontend/` (after a build):

```powershell
npm run build      # produces frontend/dist (required; the script checks for it)
npm run test:e2e
```

or directly from the repository root:

```powershell
node scripts/e2e-smoke.mjs
```

Exit code is `0` when every check passes and `1` on any failure (a startup
error, a failed check, or a readiness timeout). A one-line summary
(`N passed, N failed, N skipped`) is printed at the end. If the backend venv
lives elsewhere, set `PHISHGUARD_E2E_PYTHON` to the interpreter path.

---

## 6. Isolation, safety and cleanup guarantees

- **Repository database never used.** The child always receives a
  `PHISHGUARD_DATABASE_PATH` inside a fresh temp directory; `backend/phisguard.db`
  is not read or written (verified: its mtime stayed `2026-10-18 12:15:58`,
  24,576 bytes, across all runs).
- **No external calls.** `VIRUSTOTAL_API_KEY` and every ambient `PHISHGUARD_*`
  variable are removed from the child environment, so the optional lookup stays
  disabled (asserted at runtime: `threat_intel.status == "disabled"`).
- **Loopback only.** Both children are launched with `--host 127.0.0.1`, and the
  script additionally inspects `netstat -ano` to prove no `0.0.0.0`/`[::]`
  listener appeared for its ports (Windows; reported as *skipped*, never
  *passed*, elsewhere).
- **Cleanup always runs.** Teardown is in a `finally` block plus signal handlers,
  so it also runs when a check throws. This was verified on the failure path
  (§7.2): after a forced failure, the temp directory, child processes and
  listeners were all gone.
- **No arbitrary sleeps.** Synchronisation uses bounded polls for readiness and
  for "has the backend stopped answering yet". The only timers are a per-request
  abort timeout and the poll interval.
- **No flaky network dependency.** Only loopback sockets and local processes are
  involved; there is no external network in any check.

---

## 7. Phase 4 — Validation results

All commands were run on 2026-10-19. Exit codes are the actual observed values.

### 7.1 Automated suites (unchanged from Day 19 where no source changed)

| Check | Command | Result | Exit |
| --- | --- | --- | --- |
| Backend suite | `python -m pytest -q` (in `backend/`) | **331 passed**, 1 warning, 3.25 s | 0 |
| Deployment artefacts | `python -m pytest tests/test_deploy_artifacts.py -q` | **36 passed**, 0.26 s | 0 |
| Frontend suite | `npm test` (in `frontend/`) | **3 files / 35 tests passed**, 3.61 s | 0 |
| Lint | `npm run lint` | **0 problems** | 0 |
| Type-check + build | `npm run build` | 35 modules; `index-DQmeeZmu.css` 29.77 kB (5.92 kB gzip); `index-DW3KsOvZ.js` 278.68 kB (87.66 kB gzip); 218 ms | 0 |
| Script syntax | `node --check scripts/e2e-smoke.mjs` | OK | 0 |

The build output hashes are identical to Day 19 — expected, because no
application source changed. The remaining pytest warning is third-party
(`StarletteDeprecationWarning` about `httpx` in `fastapi/testclient.py`).

### 7.2 New end-to-end smoke test

| Run | Command | Result | Exit |
| --- | --- | --- | --- |
| Happy path | `node scripts/e2e-smoke.mjs` | **18 passed, 0 failed, 0 skipped** | 0 |
| Happy path (npm entry) | `npm run test:e2e` | **18 passed, 0 failed, 0 skipped** | 0 |
| Failure path (forced) | `PHISHGUARD_E2E_PYTHON=<missing>` then `node scripts/e2e-smoke.mjs` | Timed out waiting for the backend, reported the spawn error, **cleaned up** (no temp dir, no processes, no listeners); summarised as `1 failed` | 1 |

The 18 checks are: backend ready; frontend ready; loopback-only bind; empty
database; `POST /api/analyze` 200; Critical ≥ 50; threat intel disabled;
isolated DB file on disk; history detail; history list; unknown id 404; CORS
allowed origin; CORS denied origin; SPA shell for `/`; SPA shell for
`/result/1`; SPA shell for `/result/999999`; requests fail when stopped; history
survives a restart.

### 7.3 Manual real-browser pass (NOT automated)

Distinct from the automated checks above: a Chromium session against the **real**
backend (`127.0.0.1:8000`, temp DB) and the **real** Vite dev server
(`127.0.0.1:5173`), driven through the harness browser tools. This exercises what
the script cannot: React DOM against a live backend and a browser's CORS
enforcement.

Observed (manually, not asserted by any repeatable script):

1. Dashboard loads with the URL form.
2. Submitting `http://paypal.com.secure-login.evil.net/verify-account`
   navigates to `/result/1` showing **Critical 80/100**, the host, registered
   domain `evil.net`, four weighted findings, and threat intelligence
   "Not configured / No verdict".
3. `/result/999999` shows **"Scan not found"**.
4. Back on the dashboard, the history lists the scan: `/result/1`,
   `paypal.com.secure-login.evil.net`, `Critical`, `80/100`.
5. **CORS in a real browser:** the Network panel shows `OPTIONS` preflight then
   `POST /api/analyze` / `GET /api/history` to `http://localhost:8000`
   succeeding, with no console errors (only the React DevTools info line).
6. **Failure and recovery in a real browser:** with the backend stopped, the
   dashboard Refresh showed *"Could not reach the PhishGuard API. Is the backend
   running?"*; after restarting the backend, Refresh restored the history item.
7. Teardown: tab closed; both servers stopped; temp directory removed; no stray
   `python`/`node` processes; only normal `TIME_WAIT` sockets remained.

---

## 8. Remaining limitations

- **`scripts/e2e-smoke.mjs` is not a browser.** It does not execute the React
  bundle, so it cannot itself verify the rendered result page/DOM, a browser's
  CORS enforcement, or the configured API base URL at runtime. Those are covered
  by the existing jsdom suite (DOM, stubbed fetch) and by the manual browser pass
  in §7.3 — the latter is **not** repeatable by a grader.
- **A build is a prerequisite.** The script checks for `frontend/dist/index.html`
  and fails with a clear message if it is missing; it does not build for you.
- **The `netstat` loopback check is Windows-only** and is reported as *skipped*
  on other platforms.
- **Small port race.** Free ports are chosen by binding to port 0 and releasing;
  a another process could in principle take the port before the child binds. The
  children use `--strictPort`/explicit ports, so a collision fails fast.
- **No automated guard against a non-loopback bind.** This is by design: an ASGI
  app cannot reliably observe uvicorn's `--host`, so a bind guard would give
  false confidence (see Day 16/19). Keeping the servers on loopback is an
  operational/pre-launch responsibility.
- **Deployment-validation tools remain absent** (`nginx`, `docker`, `openssl`,
  `sqlite3`), and the app remains **unauthenticated** — the history endpoints
  are still open on whatever interface the process is told to bind. That risk is
  unchanged from Day 19 and is only acceptable while the process stays on
  loopback (see `backend/eval/DAY19_REPORT.md`).

---

## 9. Is the local demo ready?

**Yes, for the documented local-only demo scope.** The three test layers now
complement each other:

- unit/component (Node + jsdom, stubbed) — 35 frontend tests;
- API/contract (pytest `TestClient`) — 331 backend tests + 36 deployment tests;
- **live end-to-end (real processes, real HTTP, real SQLite, real CORS headers)**
  — 18 checks, repeatable via `npm run test:e2e`.

The end-to-end flow (submit → result → history → unknown id → failure/recovery)
and clean teardown are demonstrated. This is **not** a claim of production
readiness, real-world phishing-detection accuracy, or a security audit. The
demo remains **local-only**: authentication is absent, TLS is absent, and the
loopback bind is the only access control. The acceptance of unauthenticated
history remains conditional and lapses if the API is ever bound beyond loopback,
port-forwarded, container-published, or proxied without authentication.
