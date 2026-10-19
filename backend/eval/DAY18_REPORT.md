# Day 18 — Frontend Integration Testing and Readiness Review

**Date:** 2026-10-19
**Scope:** local-only college demonstration. Nothing in this report claims that
PhishGuard is safe for public deployment, has passed a security audit, or
detects real-world phishing at any particular accuracy.
**Previous reports:** `DAY6`–`DAY12`, `DAY15`, `DAY16`, `DAY17`. This file is
new; no earlier report was modified or overwritten.

---

## 1. Summary

| Phase | Outcome |
| --- | --- |
| 1 — Baseline | Re-measured, **not** taken from the Day 17 report. All five commands reproduced Day 17 exactly (17 / 0 / build 0 / 331 / 36, all exit 0). Working tree unchanged since Day 17. |
| 2 — Test strategy | The seven prioritised integration behaviours cannot be automated without a DOM environment. A dependency proposal was presented and **approved**; **51 packages** were added (no `--force`, no `--legacy-peer-deps`, Vite untouched). **10 component/integration tests** were written, taking the frontend suite from **17 → 35 tests**. |
| 3 — Honest docs | README reviewed against the six required statements: five inaccuracies/gaps found and fixed, plus two follow-up edits once component tests existed. Nothing was found claiming a security audit or production readiness. |
| 4 — Validation | Full re-run after every change: **35** frontend / **331** backend / **36** deploy, lint 0, build 0, `npm audit` 0 vulnerabilities. A live browser round trip was re-verified. One incidental defect was found and fixed (§4.7). |
| 5 — Report | This file. |

**Bottom line:** the local demo remains ready and working end to end, and the
frontend integration behaviours are now covered by automated tests instead of a
manual checklist.

---

## 2. Starting state (re-measured, not assumed)

The Day 17 report was treated as historical. Every number below was produced by
re-running the command in this session before any change was made.

| Item | Value |
| --- | --- |
| Node.js | 24.17.0 |
| npm | 11.13.0 |
| Vite (installed) | 8.3.4 |
| Vitest (installed) | 5.0.5 |
| TypeScript | 6.0.3 (`~6.0.2`) |
| React / react-dom / react-router-dom | 19.2.8 / 19.2.8 / 7.18.4 |
| Python | 3.12.10 |
| Vitest config file | **none** (no `vitest.config.*`, and no `test` block in `vite.config.ts`) |
| Vitest defaults in use | `environment: 'node'`, `globals: false` (tests import `describe/it/expect/vi` explicitly) |
| `frontend/.env` | **absent** (only `.env.example`), so the client default `http://localhost:8000` applies |
| Git repository | **still none** (`git rev-parse` → exit 128); all changes exist on disk only |

### 2.1 Baseline command results (before any change today)

| Command | Output | Exit |
| --- | --- | --- |
| `npm test` (`vitest run`) | `Test Files 1 passed (1)` / `Tests 17 passed (17)`, 276 ms | 0 |
| `npm run lint` (`oxlint`) | no output (0 problems) | 0 |
| `npm run build` (`tsc -b && vite build`) | `35 modules transformed`, `index-DQmeeZmu.css 29.77 kB / gzip 5.92 kB`, `index-DW3KsOvZ.js 278.68 kB / gzip 87.66 kB`, built in 221 ms | 0 |
| `python -m pytest -q` (backend) | `331 passed, 1 warning in 5.42s` | 0 |
| `python -m pytest tests/test_deploy_artifacts.py -q` | `36 passed in 0.29s` | 0 |

The single warning is unchanged and third-party:

```
backend\.venv\Lib\site-packages\fastapi\testclient.py:1
  StarletteDeprecationWarning: Using `httpx` with `starlette.testclient`
  is deprecated; install `httpx2` instead.
```

The reported Day 17 baseline therefore **reproduces exactly**.

---

## 3. Phase 1 — code inspection

Files read (not modified) to establish what actually needs testing:

| File | Relevant behaviour observed |
| --- | --- |
| `src/App.tsx` | `ResultRoute` wraps `ResultPage` with `key={id}`, deliberately remounting on id change so loading/error/not-found state cannot leak between results. Routes: `/`, `/result/:id`, `*` → not-found page. |
| `src/pages/Dashboard.tsx` | `useEffect` → `getHistory(15)`; `handleAnalyze` → `analyzeUrl(trimmed)` then `navigate('/result/' + id)`. Separate `loading`/`error` state for the form and for the history list. |
| `src/pages/ResultPage.tsx` | `useEffect` → `getScan(id)`; branches on `ApiError.status === 404` → "Scan not found"; renders gauge + badge + details + findings + threat-intel panel. |
| `src/components/UrlForm.tsx` | Controlled input with `id="url"`, `<label class="sr-only">URL to analyze</label>`, submit disabled while `value.trim()` is empty or loading. |
| `src/components/HistoryList.tsx` | Four explicit states: loading spinner, error + `Refresh` in a `role="alert"`, empty ("No scans yet…"), populated list. |
| `src/components/{RiskBadge,RiskGauge,FindingList,Spinner,ThreatIntelPanel}.tsx` | Badge renders `{label} {score}/100`; gauge SVG is `aria-hidden="true"`; spinner uses `role="status" aria-live="polite"`; `ThreatIntelPanel` handles `intel === null`. |
| `src/lib/risk.ts` | `riskThemes: Record<RiskLabel, RiskTheme>` and `severityColor()` with a `default` branch. |
| `src/api/client.ts` | `request()` at 104–146, `ApiError` at 94–102, `analyzeUrl`/`getHistory`/`getScan` at 148–161. Network failure → `ApiError(status 0)` with "Could not reach the PhishGuard API. Is the backend running?". |
| `package.json` | scripts `dev`, `build` (`tsc -b && vite build`), `lint`, `test` (`vitest run`), `test:watch`, `preview`. |
| `vite.config.ts` | `server.host: '127.0.0.1'`, `port: 5173`. No `test` block. |

No scoring, weighting or threshold code was read for modification, and none was
changed. `backend/app/analyzer.py` and the risk thresholds are untouched.

---

## 4. Phase 2 — testing strategy

### 4.1 Behaviour-by-behaviour gap analysis (as measured before the change)

| Prioritised behaviour | What it actually requires | Automatable on the Day 17 stack? |
| --- | --- | --- |
| Dashboard loading + API failure handling | Run `useEffect`, resolve/reject a stubbed `fetch`, re-render | **No** |
| URL scan submission | Controlled input, synthetic events, submit guard | **No** |
| Rendering risk level and score | Render after an async state transition | **No** |
| History loading, empty and error states | Drive `getHistory` to each of its three outcomes | **No** |
| Navigating between different scan ids | Interactive router, `key={id}` remount | **No** |
| Retry behaviour | Click `Refresh`/`Retry` after a rejected request | **No** |
| Accessible error messages | Assert a `role="alert"` node appears with the right text | **No** |

Every row needs exactly one missing capability: **a DOM environment plus a
renderer that can execute React updates**. `react-dom/server` provides neither
(effects never run), and Vitest's `node` environment has no `document`.

### 4.2 Options considered

| Option | Verdict |
| --- | --- |
| **A. Keep testing manually in the browser** | Works (§7) but is not repeatable or regression-proof, and cannot run in `npm test`. |
| **B. `react-dom/server` static rendering (zero deps)** | **Adopted as a complement**, not a substitute — it covers none of §4.1. |
| **C. `react-test-renderer`** | **Rejected.** Deprecated in React 19, and still provides no DOM for event simulation. |
| **D. Vitest browser mode (`@vitest/browser` + Playwright/WebdriverIO)** | **Rejected.** Real browser, but a far larger dependency and configuration footprint than this project needs. |
| **E. Hand-rolled DOM shim** | **Rejected.** Large and brittle; it would become the thing that needs testing. |
| **F. `jsdom` + Testing Library** | **Chosen and approved.** The only option covering §4.1 with maintained, mainstream packages. |

No `sleep`, timer-based or real-network test was added. Every request in every
component test is served from an in-memory stub, and an unmocked URL returns a
loud `599` rather than looking like an outage, so a test cannot pass for the
wrong reason.

### 4.3 Compatibility research (npm registry, queried live)

| Package | Version | Engines | Peers checked |
| --- | --- | --- | --- |
| `jsdom` | `^30.1.3` | `^22.22.2 \|\| ^24.15.0 \|\| >=26.0.0` → **Node 24.17.0 OK** | optional `canvas` (not needed, not installed) |
| `@testing-library/react` | `^16.3.3` | `>=18` → OK | `react ^18 \|\| ^19` (**19.2.8 OK**), `react-dom` (OK), `@testing-library/dom ^10` (**required peer**), `@types/react*` optional (present) |
| `@testing-library/dom` | `^10.4.2` | `>=18` → OK | none |
| `@testing-library/user-event` | `^14.6.8` | `node >=12` → OK | `@testing-library/dom >=7.21.4` (satisfied) |

Only the `@testing-library/react` 16.x line accepts React 19 (6 versions:
`16.1.0`–`16.3.3`). Because 16.x lists `@testing-library/dom ^10` as a
**non-optional** peer, that package had to be installed explicitly rather than
being pulled in transitively.

### 4.4 Dependency change — approved and installed

Approved by the user, then installed exactly as proposed:

```powershell
npm install --save-dev jsdom@30.1.3 "@testing-library/react@16.3.3" "@testing-library/dom@10.4.2" "@testing-library/user-event@14.6.8"
```

Actual result:

```
added 51 packages, and audited 118 packages in 36s
found 0 vulnerabilities
INSTALL EXIT: 0
```

Verification after installing:

| Check | Result |
| --- | --- |
| `npm ls vite` | still a **single deduped `vite@8.3.4`** (no upgrade, no duplicate) |
| `npm ls` for the new packages | `jsdom@30.1.3` deduped, `@testing-library/dom@10.4.2` deduped, `@testing-library/react@16.3.3`, `@testing-library/user-event@14.6.8` |
| `package-lock.json` entries | exactly **1** `node_modules/vite`, **1** `node_modules/vitest`, **1** `node_modules/jsdom` |
| `npm audit` | `found 0 vulnerabilities` |
| `--force` / `--legacy-peer-deps` | not used, at any point |

Cost, stated plainly: the audited package count went from **67 → 118**. That
was the trade-off the approval was based on.

No Vitest configuration file was created and `vite.config.ts` was **not**
changed. The jsdom environment is opted into per file with
`// @vitest-environment jsdom`, so the fast Node environment is retained for the
existing pure-logic suite. Because Vitest runs with `globals: false`, Testing
Library's automatic cleanup is not registered, so each DOM test file calls
`afterEach(cleanup)` explicitly.

### 4.5 Render smoke tests (added without any dependency)

`frontend/src/app-render.test.tsx` — 8 tests rendering the real component tree
to static HTML with `react-dom/server` inside a `MemoryRouter`:

| # | Test | Asserts |
| --- | --- | --- |
| 1 | dashboard renders at `/` | heading, `URL to analyze` sr-only label, `Analyze URL`, `Recent scans`, loading branch |
| 2 | no alert before anything fails | `role="alert"` absent from initial markup |
| 3 | loading exposed to assistive tech | `role="status"` present |
| 4 | submit disabled until a URL is entered | `disabled=""` on first render |
| 5 | result route loading state | `Loading analysis` for `/result/1` |
| 6 | result route has a route back | `New scan` link |
| 7 | unknown route | `Page not found` + `Back to dashboard` |
| 8 | render purity | `fetch` is **never** called while rendering `/`, `/result/1`, `/result/999999`, `/nope` |

Kept because it is the only automated check of the page/route layer and it pins
the render path as side-effect free. It deliberately does **not** run effects,
submit the form, or observe data/error/not-found branches.

### 4.6 Component / integration tests (10 tests, new)

File: **`frontend/src/app.integration.test.tsx`** (jsdom). Every test renders the
real `App` inside a `MemoryRouter` and stubs `fetch`.

| # | Behaviour | Test |
| --- | --- | --- |
| 1 | history loading → empty | holds the request open with a test-controlled promise, asserts `role="status"` + `Loading history…`, then resolves and asserts the empty state; also asserts the dashboard requests `/api/history?limit=15` |
| 2 | history rendering | two stored scans render host, label and score badge, and link to `/result/1` |
| 3 | **history failure + retry** | first request rejects → `role="alert"` whose text is exactly `Could not reach the PhishGuard API. Is the backend running?`; clicking `Refresh` loads the list and clears the alert |
| 4 | **URL submission** | types a URL with surrounding whitespace, submits, lands on the result page; asserts the trimmed body `{"url":"http://…"}` and the `Content-Type` header that were actually sent |
| 5 | submission guard | `Analyze URL` stays disabled for empty and whitespace-only input, and no analyze request is made |
| 6 | **result rendering** | score `80/100`, label `Critical`, findings, the "no intel recorded" branch, the amber disclaimer, no alert, and **every `svg` is `aria-hidden="true"`** (the score is also text) |
| 7 | not-found | 404 → `Scan not found` + explanation + `Back to dashboard`, and **no** alert (the 404 branch must not be reported as an error) |
| 8 | **non-404 error + retry** | 500 with `{"detail": "Database is unavailable."}` → alert contains that message and does *not* say "not found"; `Retry` then loads the scan and clears the alert |
| 9 | **id change: not-found → data** | navigates `/result/999999` → `/result/1` **within the same router** (so `ResultRoute` stays mounted). This is the keyed-remount regression test: without `key={id}` the stale `notFound` flag would keep the real scan hidden. |
| 10 | **id change: data → data** | navigates `/result/1` → `/result/2`; asserts scan B is shown and scan A's host and label are gone |

Coverage of the seven prioritised behaviours: dashboard loading (1), API failure
handling (3, 8), URL submission (4, 5), risk level and score rendering (4, 6),
history loading/empty/error (1, 2, 3), navigation between result ids (9, 10),
retry (3, 8), accessible error messages (3, 8).

Two honest notes about the tests themselves:

- Two test-side bugs were found and fixed while writing them, and both are
  recorded rather than hidden: the host text appears **twice** on the result page
  (the `h1` and the "Host" detail row), so `getByText(host)` is ambiguous and
  assertions must query by role + name; and an unnamed
  `findByRole('heading', { level: 1 })` matched the dashboard's `h1` *before*
  navigation completed, letting a test assert the wrong page. Neither was an
  application bug.
- Tests render `App` without `React.StrictMode`. StrictMode's development-only
  double invocation of effects is verified manually in a browser, not here.

### 4.7 Incidental defect found and fixed: test code leaking into production CSS

Found by measuring, not by guessing. After the test files were added, the
production stylesheet grew from `29.77 kB` to `30.04 kB` (+0.27 kB, gzip
5.92 → 5.97 kB) and its content hash changed.

Cause: Tailwind 4's automatic content detection scans source files and generates
a utility for any identifier that looks like a class name. The test line
`const { container } = renderApp('/')` therefore emitted the whole `.container`
utility into the shipped CSS. Verified by parsing the built CSS and comparing
selector classes against every source file: **exactly 1** class (`container`)
was explainable only by a test file.

Fix: `frontend/src/index.css`

```css
@source not '**/*.test.ts';
@source not '**/*.test.tsx';
```

Verified after the fix: selector classes went `301 → 300`, classes explainable by
test files went `1 → 0`, and the rebuilt CSS is `29.77 kB / gzip 5.92 kB` with the
same content-hash filename as the pre-test baseline (`index-DQmeeZmu.css`). The
JS bundle was never affected (`278.68 kB`, 35 modules, byte-identical throughout).

---

## 5. Phase 3 — honesty and documentation review

The README and `deploy/README.md` were reviewed against the six required
statements.

| Required statement | Status before | Action |
| --- | --- | --- |
| Local-only demonstration | Stated, but with a **now-false detail** | **Fixed** |
| History API has no authentication | Already stated ("its history endpoints are unauthenticated") | None |
| Scanner uses heuristics | Already stated | None |
| VirusTotal separate from heuristic scoring | Already stated: "**Separate from scoring** … It **never** changes `risk_score` / `risk_label`" | None |
| Real-world detection accuracy not established | **Missing from the README**, while `EVALUATION_REPORT.md` shows a bare `Accuracy: 0.667` from 12 synthetic cases | **Added** |
| Deployment templates not validated | Stated in detail in `deploy/README.md` and pinned by tests | None |
| No claim of a security audit / production readiness | No such claim; one ambiguous phrase | **Clarified** |

Edits made to `README.md` (7 total):

1. **Stale fact corrected.** Said the dev server sets `server.host` to
   `localhost`; it has been `127.0.0.1` since Day 17. Now states the IPv4
   loopback bind, both working URLs, and why IPv4 was chosen.
2. **Missing accuracy disclaimer added** to "Known limitations":
   > **Real-world detection accuracy has not been established.** The only
   > evaluation in the repository is a 12-case *synthetic* fixture set … The
   > accuracy, precision and recall figures there describe that tiny
   > constructed set only — they are **not** a real-world detection rate, and no
   > external PhishTank/Tranco-style dataset has been evaluated
   > (`backend/eval/data/` does not exist). Do not quote those numbers as
   > performance of the tool.
3. **Tech-stack table** `Testing` row now reads `pytest (+ FastAPI TestClient),
   Vitest`.
4. **Project-structure comment** `DAY6..DAY16` → `DAY6..DAY18`.
5. **Ambiguity removed:** "`DAY12_REPORT.md` for the **audit** behind them" →
   "for the **review** behind them".
6. **§3 rewritten** (twice, to stay true): it now describes three frontend
   suites, the per-file jsdom environment, and that `fetch` is stubbed with no
   timers or real network calls. The first version said effects/submission/
   navigation were "covered by manual browser checks only" — true at that
   moment, false once §4.6 landed, so it was corrected.
7. **Structure listing** gained a line for the test files.

No previous report was modified. No security claim was added or strengthened.
`deploy/README.md` was left unedited because its "nothing here was executed or
validated on a real host" statement is accurate.

---

## 6. Phase 4 — validation (final, after all changes)

| Command | Result | Exit |
| --- | --- | --- |
| `npm test` (`vitest run`) | `Test Files 3 passed (3)` / `Tests 35 passed (35)`, 2.98 s | **0** |
| `npm run lint` (`oxlint`) | 0 problems | **0** |
| `npm run build` (`tsc -b && vite build`) | 35 modules, `index-DQmeeZmu.css 29.77 kB / 5.92 kB gzip`, `index-DW3KsOvZ.js 278.68 kB / 87.66 kB gzip`, 232 ms | **0** |
| `python -m pytest -q` (full backend suite) | `331 passed, 1 warning` | **0** |
| `python -m pytest tests/test_deploy_artifacts.py -q` | `36 passed` | **0** |
| `npm audit` | `found 0 vulnerabilities` | **0** |
| `npx vitest run` (repeat runs) | 35 passed, 0 skipped, 0 todo | **0** ×5 |

Frontend tests went **17 → 35**: `src/api/client.test.ts` (17),
`src/app-render.test.tsx` (8), `src/app.integration.test.tsx` (10).

Notes on what these numbers prove:

- `npm run build` runs `tsc -b` first, so the **new test files are type-checked**
  as part of the build, and `oxlint` lints them. Both pass. A type-broken test
  breaks the build — intentional since Day 17.
- The production bundle is **unchanged**: 35 modules and byte-identical JS
  before and after adding ~18 kB of test code, confirming tests are not bundled.
- The final CSS is byte-identical to the pre-test baseline after the §4.7 fix.
- The README edits were validated *after* being made, because
  `test_deploy_artifacts.py` asserts root-README substrings
  (`uvicorn app.main:app --reload`, `npm run dev`, `ops/db_lifecycle.py`). All 36
  documentation tests still pass.

### 6.1 Test-run stability (reported honestly)

Five consecutive full-suite runs passed after the assertions were fixed.
**One** earlier run failed for a non-test reason: Vitest reported
`[vitest-pool]: Failed to start forks worker for test files
…src/app.integration.test.tsx` / `Timeout waiting for worker to respond`, the run
took 670 s, and the two Node-environment files still passed. No stray `node`
processes were present and the very next runs were clean, so this is an
environment-level worker-spawn failure (Windows + OneDrive-backed working
directory + antivirus), not a failing test and not reproducible. It is recorded
here because it was observed. Mitigations if it recurs: `vitest --pool=threads`,
or an explicit fork-pool timeout.

There are no `sleep`s, no timers, no polling and no network access in any test,
which is what keeps the suite deterministic once the worker starts.

---

## 7. Phase 4 — live browser verification

Two browser sessions were run against the real stack on a throwaway database
(`%TEMP%\opencode\day18*.db`), so the repository database was never touched.

```
backend  : uvicorn app.main:app --reload --host 127.0.0.1
frontend : npm run dev  →  VITE v8.3.4 ready, Local: http://127.0.0.1:5173/
```

### 7.1 Session 1 — before the dependency change

| Check | Result |
| --- | --- |
| Listeners | `127.0.0.1:5173` and `127.0.0.1:8000` only; **`0.0.0.0` bind present: False** |
| `http://localhost:5173/` and `http://127.0.0.1:5173/` | **200** both |
| `/api/health` on `localhost:8000` and `127.0.0.1:8000` | **200** both |
| Dashboard initial load | labelled URL textbox, `Analyze URL` disabled, three examples, `RECENT SCANS`, spinner |
| History empty state | `No scans yet. Analyze a URL to build your history.` — no infinite loading |
| Submit `http://paypal.com.secure-login.evil.net/verify` | `OPTIONS` 200 → `POST /api/analyze` 200 → `/result/1` |
| Result page | host `paypal.com.secure-login.evil.net`, **Critical 80/100**, no alert, **0** unlabelled SVGs |
| `/result/999999` then back to `/result/1` | `Scan not found` shown, then the real scan with **no leaked not-found text or alert** |
| Return to dashboard | new scan appears in history |
| Simulated API outage (rejecting `fetch`) + `Refresh` | `<div role="alert">` containing exactly `Could not reach the PhishGuard API. Is the backend running?`; previously loaded history stayed visible |
| Restore `fetch` + `Refresh` | alert cleared, history re-rendered |
| Console (warning and above) | **0 messages** |
| Network | 3 × `GET /api/history?limit=15` → 200; `OPTIONS`/`GET /api/history/1` → 200; `OPTIONS`/`GET /api/history/999999` → **404** (expected) |

### 7.2 Session 2 — after the `index.css` change

Re-checked because §4.7 touched the stylesheet pipeline:

| Check | Result |
| --- | --- |
| Styling still applied in the dev server | `body` background `rgb(2, 6, 23)` (slate-950), font `Inter, ui-sans-serif, …`, `h1` 48 px white |
| Leaked `.container` in the DOM | **false** |
| Submit → result flow | `/result/1`, host `paypal.com.secure-login.evil.net`, no alert, **0** unlabelled SVGs |
| Console (warning and above) | **0 messages** |

### 7.3 Teardown

| Item | Result |
| --- | --- |
| Browser tabs | all `localhost:5173` tabs closed |
| Listeners on 8000 / 5173 | **none** — both ports released |
| Remaining `node`/`python` processes | **none** |
| `0.0.0.0` listeners from our services | **none** |
| Temp databases `day18.db`, `day18b.db` | deleted |
| Temporary scratch directory used for the §4.7 measurement | deleted |
| `backend\phisguard.db` | **untouched** — `LastWriteTime 2026-10-18 12:15:58`, 24 576 bytes |

Both background dev-server shells report exit code 1 because they were stopped
with `Stop-Process`; that is teardown, not an application failure.

Other observations, recorded rather than explained:

- Requests appear doubled in the uvicorn log (`OPTIONS`+`GET` twice). This is
  React `StrictMode` double-invoking effects in development; the production build
  does not do this.
- Unidentified external `GET /health` → **404** probes hit uvicorn again
  (also seen on Day 16 and Day 17). Nothing in this project requests `/health`
  (the app uses `/api/health`).
- Vite printed `Re-optimizing dependencies because lockfile has changed` on the
  first dev start after the install. Expected.

---

## 8. New dependencies

Four direct devDependencies were added, with 51 transitive packages
(67 → 118 audited packages):

| Package | Version | Purpose |
| --- | --- | --- |
| `jsdom` | `^30.1.3` | DOM environment for component tests |
| `@testing-library/react` | `^16.3.3` | Render components and flush React updates |
| `@testing-library/dom` | `^10.4.2` | Required by the above; accessible role/name queries |
| `@testing-library/user-event` | `^14.6.8` | Realistic typing and clicking for the form and retry buttons |

Still **not** installed, deliberately: Playwright/WebdriverIO,
`@vitest/browser`, `react-test-renderer`, `happy-dom`, `@testing-library/jest-dom`,
and any code-coverage tooling.

`vite` was **not** upgraded or duplicated (still one deduped `8.3.4`), no
`--force` and no `--legacy-peer-deps` was used, and `npm audit` reports 0
vulnerabilities.

---

## 9. Remaining bugs and limitations

### 9.1 Security limitations (unchanged, restated honestly)

- **The history API is still unauthenticated.** `GET /api/history` and
  `GET /api/history/{id}` return every stored scan to anyone who can reach the
  port. This is Day 16 finding **H-1** and remains an unresolved product
  decision, not a fixed defect. On a single-user loopback-only machine the risk
  is contained by the bind address alone.
- The loopback bind is the **only** access control: no authentication, no TLS,
  no per-user isolation, no sessions.
- Requests are HTTP in cleartext between browser and API on the same machine.
- CORS (`http://localhost:5173`, `http://127.0.0.1:5173`) is **not** a security
  boundary — it is enforced by browsers only.
- The rate limiter is disabled by default and is process-local.
- SQLite and the `ops/` backups store submitted URLs in cleartext, with no
  retention policy.
- `backend/phisguard.db` is git-ignored but **present on disk** and may contain
  URLs typed during manual testing. Any artefact handed to a grader should
  exclude it, along with `ops/` backups.

### 9.2 Testing gaps that remain

- No end-to-end test against a real backend. Process start, CORS preflight,
  SQLite persistence and the real analyzer output are still verified manually
  (§7) or by the backend's own pytest suite.
- No DOM-level accessibility audit (e.g. axe). Accessibility is asserted only
  through explicit role/label queries and the `aria-hidden` gauge check.
- No code-coverage measurement is configured, and none is proposed.
- The suite is subject to the §6.1 worker-spawn timeout on this machine, which
  has been observed once and not reproduced.
- `tsc -b` type-checks the test files as part of `npm run build`, so a
  type-broken test breaks the build. Intentional, but it means a broken test can
  block a release build.

### 9.3 Evaluation and deployment limits

- **No real-data evaluation is possible:** `backend/eval/data/` does not exist
  (git-ignored). The only figures anywhere are the 12-case synthetic fixtures in
  `EVALUATION_REPORT.md`. No real-world accuracy claim is supported, and the
  README now says so explicitly.
- **Deployment templates remain unvalidated:** `nginx`, `caddy`, `docker`,
  `openssl` and `sqlite3` are all absent from this machine, and systemd is
  Linux-only. `deploy/*` is a reviewed template pinned by static tests, not a
  verified deployment.
- No public deployment was configured, and none should be.

### 9.4 Known non-defects (so they are not mistaken for regressions)

- `StarletteDeprecationWarning` from `fastapi/testclient.py:1` — third-party,
  1 warning, present before today.
- Duplicated requests in the dev server log — React `StrictMode`, development
  only.
- External `GET /health` 404 probes — see §7.
- Background shells exiting 1 after `Stop-Process` — teardown artefact.
- No Git repository, so nothing is committed, staged or diffable.

---

## 10. Is the local demo still ready?

**Yes.** Every claim below was re-verified in this session:

- Both services start with the documented commands and bind loopback only
  (`0.0.0.0` absent).
- The documented URL `http://localhost:5173` and the bound origin
  `http://127.0.0.1:5173` both serve the app; the API answers on both
  `localhost:8000` and `127.0.0.1:8000`.
- The full flow works: load → empty history → submit → scored result page
  (Critical 80/100) → history populated → missing id shows a clean
  "Scan not found" → back to the real scan with no leaked state → simulated
  outage produces an accessible alert → retry recovers.
- Zero console warnings or errors in either session.
- Styling is intact after the CSS change (`rgb(2, 6, 23)`, Inter, 48 px heading).
- Automated suites are green: **35** frontend, **331** backend, **36**
  deployment/documentation; lint 0; build 0; `npm audit` 0 vulnerabilities.
- Teardown left no listeners, no stray processes, no temporary databases, and
  the repository database untouched.

The demo is ready for local demonstration to a grader on this machine. It is
**not** ready for, and not intended for, any networked or public exposure.

---

## 11. Recommended next step

The blocking decision from the start of Day 18 was resolved: the dependency
question was approved and the frontend integration behaviours are now automated.
The highest-value remaining work is therefore:

1. **Resolve or explicitly document H-1** (unauthenticated history API). Decide
   whether open history endpoints are an accepted property of a loopback-only
   demo — and if so, say exactly that in the README — or whether they need
   protection.
2. **Turn the §7 browser checklist into a repeatable script or a real end-to-end
   test.** The remaining untested seam is exactly where unit tests cannot reach:
   process start, CORS, and SQLite persistence through a live server.
3. **Decide on a grader artefact policy**: keep `backend/phisguard.db` and
   `ops/` backups out of anything handed over.
4. Optional, low priority: an accessibility audit (axe) and coverage reporting,
   both of which would need new dependencies and a separate approval.

---

## 12. Claim boundary

This report contains no invented results. Every command, exit code, test count,
HTTP status, byte size and file hash above was observed in this session;
anything not run is stated as not run. Failures that occurred while writing the
tests — the two assertion bugs and the single worker-spawn timeout — are
recorded in §4.6 and §6.1 rather than omitted.

It does **not** claim: production readiness; that a security audit was
performed; that PhishGuard detects real-world phishing with any measured
accuracy; that the deployment templates work; or that the end-to-end
dev-server/real-backend path (§9.2) is covered by automated tests. It is not.
