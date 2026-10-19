# Day 16: Local-Only Scope, Frontend Lint/Accessibility Fixes, Revalidation

**Date:** 2026-10-19 (local session date on the machine where this ran)
**Environment:** Windows, PowerShell, Python 3.12.10 venv at `backend/.venv`,
SQLite 3.49.1 (Python stdlib driver), Node.js 24.17.0 / npm, Vite 8.3.4,
TypeScript 6.0.3, oxlint 1.88.0, React 19.3.1, react-router-dom 7.18.4.
**Scope:** declare and enable a *local-only* project scope, investigate the two
`set-state-in-effect` lint warnings, fix accessibility and lint issues where a
correct fix exists, revalidate everything, report actual results.

> **No Git repository exists in this workspace**
> (`git rev-parse --is-inside-work-tree` → `fatal: not a git repository`,
> exit 128). **No Git diff was produced or reviewed.** Every change listed in
> §4 was verified by re-reading the edited file afterwards, and by re-running
> the full build/lint/test suites.

---

## 1. Initial state (verified, not assumed)

### 1.1 Repository and report inventory

* **Not a Git repository.** Exit code 128, confirmed before any edit.
* `backend/eval/` contained, before this session:

  ```
  DAY6_REPORT.md  DAY7_REPORT.md  DAY8_REPORT.md  DAY9_REPORT.md
  DAY10_REPORT.md DAY11_REPORT.md DAY12_REPORT.md DAY15_REPORT.md
  EVALUATION_REPORT.md  DATASETS.md  README.md
  __init__.py  analyze_thresholds.py  evaluator.py  fixtures.jsonl  import_dataset.py
  ```

  * `DAY13_REPORT.md` and `DAY14_REPORT.md` **still do not exist** (directory
    listing). Note: `backend/tests/test_deploy_artifacts.py` contains a section
    commented "Day 13: cross-file consistency findings", i.e. Day-13 *tests*
    exist on disk but there is no Day-13 *report*. That discrepancy is recorded
    here rather than resolved.
  * `DAY16_REPORT.md` (this file) is new. **No existing report was overwritten
    or edited.**

### 1.2 Baseline re-run *before* any change (not reused from earlier sessions)

| Command (working dir) | Result | Exit |
| --- | --- | --- |
| `backend> .\.venv\Scripts\python.exe -m pytest -q` | **331 passed, 1 warning** in 5.94s | 0 |
| `frontend> npm run lint` | **exit 0, 2 warnings** | 0 |
| `frontend> npm run build` | 35 modules, `index-WZtB1Vpa.js` 278.62 kB / gzip 87.64 kB | 0 |

The two lint warnings were exactly:

```
src/pages/Dashboard.tsx:45:10: warning react(set-state-in-effect): ...
src/pages/ResultPage.tsx:46:10: warning react(set-state-in-effect): ...
```

Recreating 331/1 from a clean run was successful; the earlier reported counts
are therefore reproduced, not merely repeated.

### 1.3 Local artifacts found

| Artifact | State | Note |
| --- | --- | --- |
| `backend/phisguard.db` | present, 24 576 bytes, last written 2026-10-18 12:15 | pre-existing local database from an earlier session; `*.db` is git-ignored. It contains previously analyzed URLs. Nothing in this session wrote to it. |
| `package-lock.json` (repo root) | present, 88 bytes, `"packages": {}` | stray empty lockfile, still unresolved (Day 15 L-3). With no Git history it cannot be proven untracked, so it was left untouched. |
| `frontend/package-lock.json` | present, 66 311 bytes | real lockfile; no test-runner packages in it. |

---

## 2. Files inspected

| Area | Files read |
| --- | --- |
| Frontend source | `src/App.tsx`, `src/main.tsx`, `src/pages/Dashboard.tsx`, `src/pages/ResultPage.tsx`, `src/components/RiskGauge.tsx`, `src/components/HistoryList.tsx` (grep), `src/components/ThreatIntelPanel.tsx` (grep), `src/components/Spinner.tsx` (grep), `src/api/client.ts` (161 lines) |
| Frontend config | `package.json`, `package-lock.json` (grep), `.oxlintrc.json`, `vite.config.ts`, `tsconfig*.json` (listed) |
| Frontend deps | `node_modules/oxlint/configuration_schema.json` (grep), `node_modules/vite/dist/node/**` (grep) |
| Root | `README.md` (all 315 lines + edits), `.gitignore`, root `package-lock.json` |
| Backend tests | `tests/test_deploy_artifacts.py` (lines 280–339 read; whole file grepped) |
| Backend eval | `eval/DAY15_REPORT.md` (header + heading index) |

Nothing was modified before these reads were complete.

---

## 3. Findings, ranked

`V` = verified defect/observation with evidence · `R` = recommendation ·
`U` = unverified concern.

### HIGH

| ID | Finding | Type |
| --- | --- | --- |
| H-1 | **`GET /api/history` and `/api/history/{id}` remain unauthenticated** and return every analysed URL. Unchanged: adding authentication is a product decision (accounts/ownership) that the brief forbids introducing silently. Now explicitly re-stated in the README's new local-only section. | U |

### MEDIUM

| ID | Finding | Type |
| --- | --- | --- |
| M-1 | **The frontend has no automated tests and no test runner.** Verified three ways: `package.json` has no `test` script; no `vitest`/`jest`/`@testing-library/*`/`jsdom`/`happy-dom`/`playwright` in `package.json` *or* `package-lock.json` (grep → 0 matches); `node_modules/vitest` absent; no `*.test.*`/`*.spec.*` files anywhere in `frontend/`. Per the brief, dependencies were **not** installed — proposal in §9. | V |
| M-2 | **The two `set-state-in-effect` warnings were not caused by a synchronous `setState` in the effect body**, but by oxlint resolving into a helper called from the effect and not modelling `await`. Root cause proven with a throwaway probe (§5). Fix available and applied (§4.1, §4.2). | V |
| M-3 | The dev server only answers on `http://localhost:5173` (IPv6 loopback `::1`), not `http://127.0.0.1:5173`, although CORS allows both origins. **Pre-existing, not introduced today** — proven by a controlled A/B probe (§5.3). | V |

### LOW

| ID | Finding | Type |
| --- | --- | --- |
| L-1 | **Fixed.** `RiskGauge`'s SVG was exposed to assistive technology even though the score is already rendered as adjacent text. | V |
| L-2 | **Fixed.** Local-only intent was spread across several sections and never stated as the project's actual scope; the dev commands relied on an *implicit* uvicorn/Vite default for loopback binding. | V |
| L-3 | **Fixed.** README project-structure comment said `DAY6..DAY12 session reports`; the directory now holds `DAY6..DAY16`. | V |
| L-4 | Stray empty root `package-lock.json` (88 bytes). Left untouched — no Git history to prove it is safe to delete. | V |
| L-5 | `deploy/` templates (nginx/Caddy/systemd) are still **unvalidated**; no nginx, caddy, systemd, docker or openssl on this machine. | U |
| L-6 | Scan history is unbounded; `ops/db_lifecycle.py retention-plan` is report-only and no deletion is implemented. Unchanged. | V |
| L-7 | Real-data evaluation still cannot run: `backend/eval/data/` is git-ignored and absent. Unchanged; no results were fabricated. | V |
| L-8 | Backups written by `ops/` are cleartext SQLite files; operators must encrypt them. Unchanged. | U |

---

## 4. Changes made

### 4.1 `frontend/src/pages/Dashboard.tsx` — history loader (fixes M-2)

`loadHistory` was an `async` function that set state after `await`; oxlint still
flagged the effect that calls it (§5). It is now a promise chain in which **every
`setState` runs inside a `.then`/`.catch` callback**, which oxlint does not treat
as synchronous. Loading/error state now starts from the `useState` defaults and
is reset by the refresh **event handler**:

```tsx
const loadHistory = useCallback(
  () =>
    getHistory(15)
      .then((data) => { setHistory(data.items); setHistoryLoading(false) })
      .catch((err: unknown) => { setHistoryError(...); setHistoryLoading(false) }),
  [],
)
...
onRetry={() => { setHistoryLoading(true); setHistoryError(null); void loadHistory() }}
```

Behaviour is unchanged: initial state is already `historyLoading = true` /
`historyError = null`, and the manual "Refresh" button still shows a loading
state and clears the previous error before reloading (verified live, §7.5).

### 4.2 `frontend/src/pages/ResultPage.tsx` — scan loader (fixes M-2)

Same conversion. The three synchronous resets (`setLoading(true)`,
`setError(null)`, `setNotFound(false)`) were moved out of the loader into the
**Retry button's event handler**; the mount path gets correct initial state from
`useState`, and id changes get a fresh mount (§4.3).

```tsx
const load = useCallback(() => {
  if (!id) return Promise.resolve()
  return getScan(id)
    .then((data) => { setScan(data) })
    .catch((err: unknown) => {
      if (err instanceof ApiError && err.status === 404) setNotFound(true)
      else setError(err instanceof Error ? err.message : 'Failed to load result.')
    })
    .finally(() => { setLoading(false) })
}, [id])
...
onClick={() => { setLoading(true); setError(null); void load() }}
```

Without the handler-side resets a successful retry would have left the error
banner pinned above the result — the live Retry test in §7.6 exists specifically
to catch that.

### 4.3 `frontend/src/App.tsx` — per-id remount of the result view (correctness)

Previously a scan id change inside the same route match (browser back/forward
between two `/result/:id` URLs) reused the mounted component, so `scan`,
`error` and — most importantly — `notFound` could persist across scans. That is
why `setNotFound(false)` had to run synchronously in the loader. It now runs
never, because the route element is keyed:

```tsx
function ResultRoute() {
  const { id } = useParams<{ id: string }>()
  return <ResultPage key={id} />
}
...
<Route path="/result/:id" element={<ResultRoute />} />
```

Verified live: after a 404 rendering "Scan not found", an in-app transition to a
valid id immediately rendered that scan (§7.4).

### 4.4 `frontend/src/components/RiskGauge.tsx` — decorative SVG hidden (fixes L-1)

```tsx
{/* Decorative: the numeric score and label are rendered as text below. */}
<svg viewBox="0 0 160 160" className="h-full w-full -rotate-90" aria-hidden="true">
```

The gauge conveys no information that the adjacent `55` / `RISK SCORE` text does
not, so `aria-hidden="true"` is the correct fix rather than a duplicate
`role="img"` + `aria-label`. Verified in the live DOM (§7.3).

### 4.5 `frontend/vite.config.ts` — explicit loopback bind (fixes L-2)

```ts
server: {
  // Local-only demo: bind the dev server to the loopback interface ...
  host: 'localhost',
  port: 5173,
}
```

A **no-op in behaviour** — Vite's default is already `localhost` (§5.3 proves
both bind `::1` only) — pinned so the intent is explicit and cannot drift.
`--host` on the CLI still overrides it, so nothing is locked down beyond what
Vite already did.

### 4.6 `README.md` — local-only scope (fixes L-2, L-3)

* New **"Scope: local-only demo"** section directly under the safety warning:
  states the project is a local college project/demo for one user on loopback,
  lists the three loopback controls (`--host 127.0.0.1`, `server.host:
  'localhost'`, restricted CORS), and states plainly that **nothing is claimed
  to be safe to expose to a network or the internet** (no authentication, no TLS
  of its own, no per-user isolation, unauthenticated history), pointing to
  "Known limitations" and `deploy/README.md`.
* Backend run command now reads
  `... -m uvicorn app.main:app --reload --host 127.0.0.1` (the flag states
  uvicorn's default explicitly). The substring asserted by
  `tests/test_deploy_artifacts.py::test_root_readme_still_documents_the_local_development_commands`
  (`uvicorn app.main:app --reload`) is preserved.
* Frontend section notes the dev server is bound to `localhost` only.
* Structure comment corrected to `DAY6..DAY16 session reports`.

**No endpoint contract changed. No analyzer threshold changed. No authentication
or other dependency was added. No existing working code was rewritten for style.**

---

## 5. Investigation detail

### 5.1 Why the warnings survived the obvious fix

Moving the resets into event handlers and leaving only post-`await` `setState`
did **not** clear the warnings; they merely shifted lines
(`Dashboard.tsx:46`, `ResultPage.tsx:47`). That ruled out the naive reading of
the rule.

### 5.2 Throwaway probe (`frontend/src/lintprobe.tsx`, created and then deleted)

Four `useEffect` shapes were linted with `npx oxlint src/lintprobe.tsx`:

| Case | Shape | Flagged? |
| --- | --- | --- |
| A | `setValue(1)` directly in the effect body | **yes** (12:5) |
| B | `void loadAsync()` where `loadAsync` is `async` and calls `setValue` **after** `await` | **yes** (21:10) |
| C | `fetchData().then((n) => setValue(n))` inside the effect | no |
| D | `fetchData().catch(() => setValue(-1))` inside the effect | no |

Conclusion: this version of oxlint resolves *into* a function called
synchronously from an effect and flags any `setState` it finds, **without
modelling `await` suspension** — so cases B is a false positive. It does treat
`.then`/`.catch` callbacks as deferred. That is why the fix is a promise chain
and not a suppression. The probe file was deleted; it is not part of the repo.

### 5.3 A/B probe: did `host: 'localhost'` change the default bind?

A temporary `frontend/vite.hostprobe.config.ts` (identical to `vite.config.ts`
but **without** `server.host`, on port 5174) was started with
`npx vite --config vite.hostprobe.config.ts`:

| Server | `LocalAddress:Port` | `http://localhost:<port>/` | `http://127.0.0.1:<port>/` |
| --- | --- | --- | --- |
| default (no `server.host`), 5174 | `::1:5174` | 200 | connection refused |
| explicit `host: 'localhost'`, 5173 | `::1:5173` | 200 | connection refused |

So the explicit setting is behaviour-neutral (M-3 is pre-existing), and the dev
server is reachable at the documented `http://localhost:5173`. The probe server
was stopped and the probe config deleted.

---

## 6. Validation results (all commands re-run today, after every edit)

| Check | Command | Result | Exit |
| --- | --- | --- | --- |
| Backend tests | `backend> .\.venv\Scripts\python.exe -m pytest -q` | **331 passed, 1 warning** in 5.42s | **0** |
| Frontend lint | `frontend> npm run lint` | **0 problems** (was 2 warnings) | **0** |
| Frontend build | `frontend> npm run build` | 35 modules; `index.html` 0.65 kB; `index-DQmeeZmu.css` 29.77 kB / gzip 5.92 kB; `index-DW3KsOvZ.js` 278.68 kB / gzip 87.66 kB | **0** |
| Frontend tests | — | **none exist; nothing was run** | n/a |

`npm run build` runs `tsc -b && vite build`, so the edited TypeScript (including
the new `ResultRoute`) type-checks.

### Remaining warning (1)

```
backend/.venv/Lib/site-packages/fastapi/testclient.py:1
StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is
deprecated; install `httpx2` instead.
```

Third-party (`fastapi`/`starlette` internal), pre-existing, unrelated to project
code. Not suppressed, not pinned away. **Zero** warnings are emitted by project
code.

---

## 7. Integration checks actually performed (live, this machine)

A real `uvicorn` process (`--host 127.0.0.1 --port 8000`, throwaway database at
`%TEMP%\opencode\day16.db`) and the real `vite dev` server on 5173 were used,
plus a real Chromium tab.

**7.1 Loopback bindings (Windows `Get-NetTCPConnection -State Listen`)**

```
port 8000 → 127.0.0.1
port 5173 → ::1
```

Neither server binds `0.0.0.0`. Both were stopped afterwards (verified
`listening=False` for 8000 and 5173).

**7.2 HTTP/CORS**

| Check | Result |
| --- | --- |
| `GET /api/health` | 200 `{"status":"ok","version":"0.1.0","scans_stored":0}` |
| `GET /api/history` with `Origin: http://localhost:5173` | 200, `access-control-allow-origin: http://localhost:5173` |
| `POST /api/analyze` with the same origin | 200, ACAO echoed, `risk_score=80`, `risk_label=Critical`, `id=1` |
| `GET http://localhost:5173/` | 200, contains `id="root"` |

**7.3 Real browser (Chromium) — changed frontend code**

| Step | Observed |
| --- | --- |
| Load dashboard | Rendered; history list populated from the API |
| Gauge accessibility probe | `svg[viewBox="0 0 160 160"]` → `aria-hidden="true"`; accessible text `"55 RISK SCORE"`; 0 SVGs left unlabelled |
| Submit `http://192.168.0.1/account` | SPA navigation to `/result/2`, score 55 / **High**, full details list |
| **7.4** SPA transition `/result/999999` → `/result/1` | 999999 showed "Scan not found"; the transition to id 1 immediately rendered `paypal.com.secure-login.evil.net` with `notFound=false` — **no state leaked across ids** (the keyed remount) |
| Console | Only the React DevTools info line, plus 2 expected "404 (Not Found)" network entries from the deliberate `/api/history/999999` request. **No React warnings, no unmounted-update warnings, no console errors from project code.** |

**7.5 Dashboard "Refresh" (event-handler reset path)**

Clicked live: the list re-rendered with both stored scans, no error appeared, no
console noise.

**7.6 ResultPage error → Retry (event-handler reset path)**

`window.fetch` was overridden in-page to reject, then the app was SPA-navigated
to `/result/2`:

* offline → `role="alert"` banner "Could not reach the PhishGuard API. Is the
  backend running?" with a Retry button;
* fetch restored, Retry clicked → **banner cleared** and `192.168.0.1` rendered.

This is the specific regression the handler-side resets prevent.

**7.7 Cleanup**

Browser tab closed; ports 8000/5173 released; the throwaway
`%TEMP%\opencode\day16.db` deleted; both temporary probe files deleted. No
server is left running.

**7.8 Observations that are not project defects**

* uvicorn logged repeated `GET /health → 404` from `127.0.0.1` while the browser
  tab was open. **No project code or config requests `/health`** (grep for
  `/health` in the repo excluding `node_modules` → 0 matches; the app only uses
  `/api/health`). Source not identified; attributed to a host/dev-tool probe, not
  to PhishGuard.
* `backend/phisguard.db` exists from a previous session (see §1.3). This session
  used a throwaway database, so no test data was added to it.

**7.9 Checks NOT performed (stated honestly)**

* No frontend unit/component tests (no runner exists — §9).
* No real-data evaluation: `backend/eval/data/` absent.
* No deployment validation: `nginx`, `caddy`, `systemctl`, `docker`, `openssl`
  unavailable on this machine.
* No test of multi-worker `uvicorn`; the rate limiter remains **off** by default
  and process-local.
* No VirusTotal live call (no key configured; offline mode).

---

## 8. Local-only security limitations (explicit)

In the intended local-only configuration, and stated so the demo is not
over-sold:

* **No authentication anywhere.** `/api/history` and `/api/history/{id}` expose
  every analysed URL to anyone who can reach the port.
* **No TLS of its own.** Traffic to uvicorn is plain HTTP; a proxy would have to
  terminate TLS, and the shipped proxy templates are unvalidated.
* **Loopback bind is the only access control** (`127.0.0.1` / `::1`). If the
  process is started with `--host 0.0.0.0` or the port is forwarded, the whole
  unauthenticated API becomes reachable.
* **Rate limiting is disabled by default** and, when enabled, is per-process
  in-memory only.
* **CORS is not a security boundary**: it restricts browser origins, not direct
  HTTP clients.
* **Stored data is sensitive**: the SQLite file holds every analysed URL in
  cleartext, and `ops/` backups are cleartext files.
* **No retention, no WAL/busy-timeout tuning, single writer.**

Nothing above is claimed as deployment-ready.

---

## 9. Phase 3 deliverable: proposed frontend test dependencies (**not installed**)

Per the brief, no dependency was installed; this is the proposal awaiting
approval.

**Recommended (minimal): `vitest` only, as a `devDependency`.**

| Why | Detail |
| --- | --- |
| Needed at all | There is no runner (`M-1`). Without one, `client.ts` behaviour can only be checked by hand in a browser. |
| Why `vitest` | It reuses the existing `vite.config.ts`, so `import.meta.env.VITE_API_BASE_URL` behaves exactly as in the app — a plain Node test would crash on `import.meta.env`. |
| Why no DOM library yet | `client.ts` uses only `fetch`, `Response`, `RequestInit` and `import.meta.env` — no `window`/`document`/`localStorage`. Node 24's global `fetch` is sufficient, so `environment: 'node'` (the default) suffices and `jsdom`/`happy-dom` are **not** needed. |
| Extras that are NOT proposed | `@testing-library/react` + `jsdom` would only be needed later, for component/page tests; that is a second decision with its own review. |
| Config touch | One `"test": "vitest run"` script in `frontend/package.json`; tests as `src/api/client.test.ts`, matching existing naming. |
| Risk to confirm before installing | Vitest↔Vite **8** peer compatibility must be verified; installing may resolve a second Vite copy. This is exactly why nothing was installed unapproved. |

Planned coverage once approved: successful JSON response; 2xx non-JSON response
(the `ApiError` added on Day 15); HTTP 4xx/5xx with `{"detail": "..."}`; 4xx with
a FastAPI validation-error array; non-JSON error body falling back to the default
message; network failure → `ApiError` with `status = 0`; and query/parameter
construction for `getHistory`/`getScan`.

---

## 10. Unfinished work

1. **Frontend test runner** (M-1) — blocked on the dependency approval in §9.
2. **History authentication** (H-1) — explicit product decision, not taken.
3. **Retention / deletion** — `ops/` is report-only by design.
4. **Real-data evaluation** — `backend/eval/data/` absent; `evaluator.py` cannot
   be meaningfully run and no accuracy claim is made.
5. **Deployment templates** — unvalidated; no relevant tooling on this machine.
6. **`frontend/vite.config.ts` dev-port reachability** (M-3) — `127.0.0.1:5173`
   does not answer although CORS lists it. Harmless for the documented
   `localhost` flow; noted rather than "fixed" to avoid churn.
7. **Stray root `package-lock.json`** (L-4) — owner decision.
8. **`backend/phisguard.db`** — a real local database with analysed URLs is
   sitting in the working tree; harmless while git-ignored, but it is the kind
   of file an operator should delete or migrate before a demo.

## 11. Recommended Day 17 priorities

1. **Approve or reject the `vitest` proposal (§9)**, then add the `client.ts`
   tests — highest value per unit of effort, because that file holds all the
   error-message logic the UI depends on.
2. Decide the **history-authentication** product question (or explicitly record
   that the demo will never leave `localhost`).
3. Fix the loopback story properly: either accept `localhost` only, or bind
   `127.0.0.1` explicitly (`host: '127.0.0.1'`) so the CORS entry matches reality.
4. Add a two-line **"this is a local demo"** banner in the UI footer, so the
   scope is visible to a demo audience and not only in the README.
5. Only then consider real-data evaluation, if a labelled dataset is available.

---

## 12. Traceability of every command quoted

| Purpose | Command (working dir) | Exit |
| --- | --- | --- |
| Confirm no Git repo | `git rev-parse --is-inside-work-tree` (root) | 128 |
| List reports / artifacts | `glob backend/eval/*.md`, `read` (root) | n/a |
| Baseline backend tests | `.\.venv\Scripts\python.exe -m pytest -q` (backend) | 0 — 331 passed, 1 warning |
| Baseline lint | `npm run lint` (frontend) | 0 — 2 warnings |
| Baseline build | `npm run build` (frontend) | 0 |
| Rule probe | `npx oxlint src/lintprobe.tsx` (frontend) | 0 — cases A,B flagged; C,D clean |
| Default-host probe | `npx vite --config vite.hostprobe.config.ts` (frontend) | 0 — bound `::1:5174` |
| Listener checks | `Get-NetTCPConnection -LocalPort 8000/5173 -State Listen` | n/a |
| Live API/CORS/analyze | `Invoke-WebRequest` to `127.0.0.1:8000/api/...` | 0 (statuses in §7.2) |
| Browser E2E | Chromium tab on `localhost:5173` + `browser.*` tools | n/a (§7.3–7.6) |
| Final backend tests | `.\.venv\Scripts\python.exe -m pytest -q` (backend) | 0 — 331 passed, 1 warning |
| Final lint | `npm run lint` (frontend) | 0 — 0 problems |
| Final build | `npm run build` (frontend) | 0 |
| Cleanup | `Stop-Process` per listening PID; `Remove-Item` temp DB/probes | n/a |
