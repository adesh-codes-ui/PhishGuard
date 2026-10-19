# Day 17 — Frontend Testing Readiness: Vitest + Localhost Consistency

**Date:** 2026-10-19
**Scope:** local-only college demonstration. Nothing in this report claims that
PhishGuard is safe for public deployment, and no real-world phishing-detection
accuracy is asserted.
**Previous reports:** `DAY6`–`DAY12`, `DAY15`, `DAY16`. This file is new; no
earlier report was modified.

---

## 1. Summary

Two approved workstreams were completed and verified:

1. **Vitest was installed and 17 frontend API-client tests were added.** Vitest
   `5.0.5` was chosen from live npm registry metadata because it supports Vite
   `^8` as an **optional-free peer only** (it has no direct `vite` dependency),
   so Vite stayed at the installed **8.3.4** with a single deduped copy. No
   `--force`, no `--legacy-peer-deps`, no `jsdom`/`happy-dom`/Testing Library.
2. **The Vite dev server now binds the IPv4 loopback `127.0.0.1` instead of
   `localhost`.** Measured effect: `http://127.0.0.1:5173` changed from
   *connection refused* to *200*, while `http://localhost:5173` still returns
   200. Nothing binds `0.0.0.0`; the local-only scope is unchanged.

Validation results (actual commands, actual exit codes):

| Command | Result | Exit |
| --- | --- | --- |
| `npm test` (`vitest run`) | 1 file, **17 passed** | 0 |
| `npm run lint` (`oxlint`) | **0 problems** | 0 |
| `npm run build` (`tsc -b && vite build`) | 35 modules, built in 221 ms | 0 |
| `pytest` (backend, full suite) | **331 passed**, 1 warning | 0 |
| `pytest tests/test_deploy_artifacts.py` | **36 passed** | 0 |

The local demo remains ready: the round trip
browser(`http://127.0.0.1:5173`) → API(`http://localhost:8000`) → SQLite →
result page was exercised end to end and worked.

---

## 2. Starting state (re-measured, not assumed)

| Item | Value |
| --- | --- |
| Node.js | 24.17.0 |
| npm | 11.13.0 |
| Vite (installed) | 8.3.4 |
| `@vitejs/plugin-react` | 6.1.2 (peer `vite: ^8.0.0`) |
| `@tailwindcss/vite` | 4.3.3 (peer `vite: ^5.2 \|\| ^6 \|\| ^7 \|\| ^8`) |
| TypeScript | 6.0.3 (`~6.0.2`) |
| oxlint | 1.88.0 (`^1.81.0`) |
| Vitest | **not installed** |
| Frontend test script | **none** (`dev`, `build`, `lint`, `preview`) |
| `frontend/.env` | **absent** (only `.env.example`) |
| `.npmrc` (repo / frontend / `$HOME`) | none of the three exists |
| npm peer settings | `legacy-peer-deps=false`, `engine-strict=false`, `strict-peer-dependencies` unset |
| Day 16 baseline | pytest 331 passed / 1 warning; lint 0 problems; build 0 |

Because no `frontend/.env` exists, `import.meta.env.VITE_API_BASE_URL` is
undefined and the client's built-in default `http://localhost:8000` applies —
which is what the tests assert.

---

## 3. Task 1 — dependency safety

### 3.1 Compatibility research (npm registry, queried live)

| Vitest | `vite` requirement | Node engine | Vite 8.3.4 OK? |
| --- | --- | --- | --- |
| **5.0.5** (`latest`) | peer `^6.4.0 \|\| ^7.0.0 \|\| ^8.0.0` — **no `vite` in `dependencies`** | `^22.12.0 \|\| ^24.0.0 \|\| >=26.0.0` | **yes** |
| **4.1.12** (`V4` tag) | dependency *and* peer `^6.0.0 \|\| ^7.0.0 \|\| ^8.0.0` | `^20.0.0 \|\| ^22.0.0 \|\| >=24.0.0` | yes |
| 4.0.0 | `^6.0.0 \|\| ^7.0.0` | — | **no** |
| 3.2.7 (`V3`) | `^5 \|\| ^6 \|\| ^7` | — | **no** |

* Of 489 published Vitest versions, **33** accept Vite `^8`: all of `4.1.x`
  (from `4.1.0-beta.4`) and all of `5.0.x`.
* Vitest 5.0.x is **peer-only** on Vite, so npm reuses the project's single
  Vite instead of installing a second copy — the strongest guarantee that the
  Vite version is untouched.
* Vitest's **only non-optional peer is `vite`**. `jsdom`, `happy-dom`,
  `@vitest/ui`, `@types/node`, `@vitest/coverage-v8` and the browser providers
  are all marked optional in `peerDependenciesMeta`.
* Vite **cannot** be downgraded for this project: `@vitejs/plugin-react@6.1.2`
  declares `vite: "^8.0.0"`. That is why Vitest 3.x/4.0.x were rejected.

**Decision:** `vitest@5.0.5` (installed as `^5.0.5`). Fallback if anything
misbehaves: `vitest@^4.1.12`.

### 3.2 Dry run before installing

```
npm install --dry-run vitest@5.0.5        # exit 0
```

Output was **18 `add` lines and no `change`/`remove` lines**, and `vite` did not
appear at all:

```
add @types/estree 1.0.9        add expect-type 1.4.0      add @vitest/spy 5.0.5
add estree-walker 3.0.3        add es-module-lexer 2.3.2  add assertion-error 2.0.1
add @types/deep-eql 4.0.2      add chai 6.3.0             add @vitest/mocker 5.0.5
add why-is-node-running 3.2.1  add magic-string 1.4.3     add @types/chai 5.2.3
add tinyexec 1.3.1             add vitest 5.0.5           add std-env 4.3.0
add tinybench 6.2.2            add obug 3.0.0             add picomatch 4.0.7
add tinyglobby 0.2.17
```

No `ERESOLVE` and no peer warning was printed. The dry run wrote nothing:
`package.json` and `package-lock.json` kept their previous mtime
(`2026-10-16 23:00:43`) and hashes.

### 3.3 Real install

```
npm install --save-dev vitest@5.0.5        # exit 0
added 18 packages, and audited 67 packages in 3s
found 0 vulnerabilities
```

Vite afterwards — still a single deduped copy:

```
frontend@0.0.0
+-- @tailwindcss/vite@4.3.3
| `-- vite@8.3.4 deduped
+-- @vitejs/plugin-react@6.1.2
| `-- vite@8.3.4 deduped
+-- vite@8.3.4
`-- vitest@5.0.5
  +-- @vitest/mocker@5.0.5
  | `-- vite@8.3.4 deduped
  `-- vite@8.3.4 deduped
```

`package-lock.json` contains exactly **one** `node_modules/vite` entry. The
lockfile grew 66 311 → 75 490 bytes. Vitest's own nested `magic-string@1.4.3`
coexists with the pre-existing root `magic-string@0.30.21`; those are different
majors in different locations, not a conflict.

No `--force` and no `--legacy-peer-deps` were used at any point.

---

## 4. Task 2 — frontend tests

### 4.1 Changes

* `frontend/package.json` — added dev dependency `vitest: ^5.0.5`; added scripts
  `"test": "vitest run"` and `"test:watch": "vitest"`.
* `frontend/src/api/client.test.ts` — **new file**, 17 tests, explicit
  `import { … } from 'vitest'` (no `globals: true`, so no `tsconfig` `types`
  change was needed).

No separate Vitest config file was added: the defaults (node environment,
`**/*.{test,spec}.?(c|m)[jt]s?(x)`) are sufficient and `vite.config.ts` is
inherited.

### 4.2 Test inventory (all expectations read off `client.ts`)

| # | Test | Asserted behaviour | Impl. reference |
| --- | --- | --- | --- |
| 1 | successful JSON response | resolves to the parsed object | `request()` 138–139 |
| 2 | request shape | `POST http://localhost:8000/api/analyze`, `Content-Type: application/json`, body `{"url": …}` | 107–110, 148–153 |
| 3 | 2xx body that is not JSON | `ApiError`, message *"The API returned a response that was not JSON. Check VITE_API_BASE_URL."*, `status 200` | 138–145 |
| 4 | HTTP error, string `detail` | message = `detail`, status preserved | 118–123, 131 |
| 5 | 422 validation array | message = first `detail[0].msg` | 124–126 |
| 6 | error body not JSON | fallback `"Request failed with status 500."`, status 500 | 119, 128–130 |
| 7 | `detail` neither string nor array | fallback `"…status 503."` | 122–127 |
| 8 | `detail` array entry without `msg` | fallback `"…status 400."` | 124 guard |
| 9 | empty error object | fallback `"…status 418."` | 119 |
| 10 | network failure | `ApiError` status **0**, message *"Could not reach the PhishGuard API. Is the backend running?"* | 111–116 |
| 11 | `ApiError` identity | `instanceof ApiError`, `instanceof Error`, `name === 'ApiError'`, `.status` | 94–102 |
| 12 | 404 from `getScan` | `status 404` and `detail` message preserved (the result page branches on 404) | 118–131, 159–161 |
| 13 | `getHistory()` | `/api/history?limit=20`, no method/body | 155–157 |
| 14 | `getHistory(5)` | `/api/history?limit=5` | 155–157 |
| 15 | `getScan(7)` | `/api/history/7` | 159–161 |
| 16 | `getScan('7')` | `/api/history/7` | 159–161 |
| 17 | `VITE_API_BASE_URL` set | request goes to the overridden origin | 90–91 |

### 4.3 Notes on test design

* `fetch` is replaced with `vi.stubGlobal('fetch', …)`; `afterEach` calls
  `vi.unstubAllGlobals()`, `vi.unstubAllEnvs()`, `vi.resetModules()` and
  `vi.restoreAllMocks()` so no mock or env value leaks between tests.
* No mock ever reads `fetch` state from another test; each test installs its own
  stub and every `Response` body is read at most once.
* The base-URL override test needs `vi.stubEnv` **plus** `vi.resetModules()` and
  a dynamic `await import('./client')`, because `API_BASE_URL` is captured at
  module load (line 90). It passes reliably.
* The test file lives under `src/`, so `tsc -b` type-checks it during
  `npm run build`. That is deliberate (tests cannot drift out of type
  correctness). It also means a broken test breaks the build — accepted
  trade-off; the alternative is a separate `tsconfig.test.json`.
* `vite build` does not bundle the test file: it is not reachable from
  `index.html`. Confirmed by the unchanged bundle hashes in §7.
* No `jsdom`, `happy-dom`, Testing Library, `@vitest/ui` or coverage package was
  installed.

---

## 5. Task 3 — localhost vs `127.0.0.1`

### 5.1 The problem

| Process | Bound address |
| --- | --- |
| Vite dev server (previous config `host: 'localhost'`) | `::1` (IPv6) only |
| uvicorn (`--host 127.0.0.1`) | `127.0.0.1` (IPv4) only |

`backend/app/config.py` (line 54) and `frontend/.env.example` advertise **both**
`http://localhost:5173` and `http://127.0.0.1:5173` as allowed origins, and the
README told the reader to open `http://localhost:5173`. With the dev server on
`::1` only, the `127.0.0.1:5173` entry was dead: following the literal IP the
CORS list mentions produced a connection error.

### 5.2 Measurements (`--strictPort`, so no silent port shift; owner PID verified)

| `server.host` | Listening sockets | `localhost:P` | `127.0.0.1:P` | `[::1]:P` |
| --- | --- | --- | --- | --- |
| `'localhost'` (previous) | `::1` | 200 | **refused** | 200 |
| `'127.0.0.1'` (new) | `127.0.0.1` | 200 | 200 | refused |

`localhost` works in **both** configurations because the browser falls back
across address families; only the literal IP depends on the bind. Neither
configuration binds `0.0.0.0`.

**Correction to Day 16's evidence.** A probe log from today showed that the
Day 16 A/B probe server auto-shifted from port 5174 to 5175 because 5174 was
already occupied, so part of the Day 16 measurement table described an
unidentified process. The Day 16 *conclusion* (default/`localhost` binds `::1`
only) is correct and is independently reconfirmed by the `--strictPort`
measurement above and by the real dev server in §8. The Day 16 report itself
was left unedited as a historical record.

### 5.3 Change

`frontend/vite.config.ts`:

```ts
host: '127.0.0.1',   // was: 'localhost'
```

with the adjacent comment rewritten to explain that `localhost` resolves to
`::1` here, that binding it would leave `http://127.0.0.1:5173` unreachable even
though the backend allow-lists that origin, and that IPv4 matches uvicorn.

`README.md` §2 now states the dev server listens on `127.0.0.1:5173`, is
reachable at both `http://localhost:5173` and `http://127.0.0.1:5173`, and never
from another machine. `README.md` §3 documents `npm test` / `npm run test:watch`
and the existing `npm run build` / `npm run lint`.

**No backend change was made.** `PHISHGUARD_CORS_ORIGINS` still lists both
origins, and both were verified live (§8.3). No API contract changed. No
analyzer threshold changed.

---

## 6. Files changed

| File | Change | Size | sha256 (first 16) | mtime |
| --- | --- | --- | --- | --- |
| `frontend/package.json` | `vitest: ^5.0.5` devDep; `test`, `test:watch` scripts | 705 B | `9C07006174B4B2DD` | 2026-10-19 13:46:49 |
| `frontend/package-lock.json` | regenerated (+9 179 B) | 75 490 B | `21471BA21DB6760C` | 2026-10-19 13:46:14 |
| `frontend/vite.config.ts` | `host: '127.0.0.1'` + comment | 922 B | `E32B074F62A1F9BD` | 2026-10-19 13:46:49 |
| `frontend/src/api/client.test.ts` | **new** — 17 tests | 8 893 B | `B745A0CFAF05D634` | 2026-10-19 13:48:29 |
| `README.md` | §2 bind wording; §3 frontend test/lint commands | 17 515 B | `E024D8257C71AC6C` | 2026-10-19 13:47:59 |
| `backend/eval/DAY17_REPORT.md` | **new** (this file) | — | — | — |

Not changed: any backend source, any test, any analyzer threshold, any endpoint
path, `frontend/.oxlintrc.json`, the `tsconfig*.json` files, `deploy/`, and
`backend/phisguard.db` (mtime still `2026-10-18 12:15:58`).

---

## 7. Validation results

```
npm test                -> 1 file passed (1), 17 tests passed, 266 ms   exit 0
npm run lint (oxlint)   -> no findings                                   exit 0
npm run build           -> tsc -b + vite build, 35 modules, 221 ms       exit 0
   dist/index.html                 0.65 kB │ gzip:  0.40 kB
   dist/assets/index-DQmeeZMu.css 29.77 kB │ gzip:  5.92 kB
   dist/assets/index-DW3KsOvZ.js 278.68 kB │ gzip: 87.66 kB
pytest                  -> 331 passed, 1 warning, 2.75 s                 exit 0
pytest tests/test_deploy_artifacts.py -> 36 passed, 0.19 s               exit 0
```

The bundle file names and sizes are **identical to Day 16**
(`index-DQmeeZMu.css`, `index-DW3KsOvZ.js`), which demonstrates that neither
the new test file nor the `server.host` change alters the production bundle.

`npm run build` failed once (exit 2) before being fixed: `tsc -b` rejected
`Conversion of type '[]' to type '[string, RequestInit]'` in the test helper,
because the fetch mock was declared with no parameters. The mocks were
redeclared as `(..._args: unknown[])` and the build then passed. This is
recorded because the type-check is part of the build, not a separate step.

---

## 8. Local integration checks

Both servers were started with the documented commands (backend on a throwaway
database so `backend/phisguard.db` was not touched) and shut down afterwards.

### 8.1 Bindings (no wildcard)

```
LocalAddress LocalPort OwningProcess
127.0.0.1         5173          6224      <- vite (new config)
127.0.0.1         8000         22764      <- uvicorn --reload

any 0.0.0.0 bind on 8000/5173: False
```

Server banner: `VITE v8.3.4 ready in 460 ms ➜ Local: http://127.0.0.1:5173/`.
Uvicorn logged `Uvicorn running on http://127.0.0.1:8000`.

### 8.2 Reachability

| URL | Result |
| --- | --- |
| `http://localhost:5173/` | 200, contains `id="root"` |
| `http://127.0.0.1:5173/` | 200, contains `id="root"` — **was refused before this change** |
| `http://[::1]:5173/` | failed (IPv4 bind) |
| `http://127.0.0.1:8000/api/health` | 200 |
| `http://localhost:8000/api/health` | 200 |
| `http://[::1]:8000/api/health` | failed (uvicorn is IPv4-only) |

Health body: `{"status":"ok","version":"0.1.0","scans_stored":0}`.

### 8.3 CORS and API round trip

```
OPTIONS /api/analyze  Origin: http://localhost:5173  -> 200  allow-origin=http://localhost:5173
OPTIONS /api/analyze  Origin: http://127.0.0.1:5173  -> 200  allow-origin=http://127.0.0.1:5173
POST    /api/analyze  Origin: http://127.0.0.1:5173  -> 200  id=1 score=80 Critical
GET     /api/history?limit=5 -> 200 total=1
GET     /api/history/1       -> 200 findings=4
GET     /api/history/999999  -> 404 {"detail":"Scan not found."}
POST    /api/analyze {}      -> 422 {"detail":[{"type":"missing","loc":["body","url"],"msg":"Field required","input":{}}]}
```

The 422 and 404 bodies are exactly the two `detail` shapes the frontend tests
assert (`detail[0].msg` and a string `detail`), so the tests match the real
server, not an invented contract.

### 8.4 Browser end-to-end, run **from the new origin**

Opened `http://127.0.0.1:5173/` (`location.origin` = `http://127.0.0.1:5173`):

* Console contained only the React DevTools informational line — no errors.
* Cross-origin history load succeeded: `OPTIONS http://localhost:8000/api/history?limit=15 -> 200`
  and `GET … -> 200`; the "RECENT SCANS" list rendered, including the scan
  created over HTTP moments earlier.
* Typed `https://secure-login.example-verify.test/account` and clicked
  **Analyze URL**: `OPTIONS /api/analyze -> 200`, `POST /api/analyze -> 200`,
  navigation to `/result/3`, page showed `Medium 25/100` with the finding
  "Multiple credential/urgency keywords" (+25) and the VirusTotal panel
  correctly reporting *Not configured / No verdict*.
* Accessibility re-check from Day 16 still holds: the gauge `<svg>` has
  `aria-hidden="true"` and **0** unlabelled SVGs remain.

### 8.5 Teardown

Browser tab closed; ports 8000 and 5173 released (both `listening: False`); zero
`python.exe`/`node.exe` processes remain; the temporary database
`%TEMP%\opencode\day17.db` was deleted. `backend/phisguard.db` was never
written to during this session.

---

## 9. Warnings and environment observations

1. **pytest warning (pre-existing, third-party).**
   `StarletteDeprecationWarning: Using httpx with starlette.testclient is
   deprecated; install httpx2 instead` from
   `backend/.venv/Lib/site-packages/fastapi/testclient.py:1`. Not project code.
2. **Unexplained `GET /health` -> 404 probes.** While uvicorn was running, an
   external caller on `127.0.0.1` repeatedly requested `/health` (not
   `/api/health`) and received 404. This was first seen on Day 16 and none of
   the project's code or configuration requests that path. It is an environment
   probe (host tooling), not an application defect.
3. **Stale browser tabs.** Two tabs from earlier sessions remain open
   (`http://localhost:5173/result/999999` and `http://localhost:4173/`). They
   belong to previous days' checks and were intentionally left untouched.
4. **Forced shutdown exit code.** The background dev-server shells report exit
   code 1 because they were stopped with `Stop-Process`; that is teardown, not a
   test failure.

---

## 10. Remaining limitations (honest statement)

* **No authentication anywhere.** `/api/history` and `/api/history/{id}` are
  unauthenticated. This remains the outstanding HIGH-severity finding (H-1 from
  Day 16) and is unresolved; it is only tolerable because the demo is
  loopback-only.
* **Loopback bind is the only access control.** No TLS of PhishGuard's own, no
  user model, rate limiting off by default and process-local, and CORS is not a
  security boundary. The `127.0.0.1` dev-server bind narrows reachability; it
  does not make a publicly reachable API safe.
* **Local data is cleartext.** `backend/phisguard.db` stores submitted URLs in
  clear text and the `ops/` backup outputs are likewise cleartext.
* **Frontend test coverage is narrow.** The 17 tests cover only
  `src/api/client.ts` with a mocked `fetch`. There are no component/DOM tests,
  no coverage measurement, and the tests never contact the real backend — the
  integration checks above were performed manually today.
* **Base-URL override relies on runtime env stubbing.** Test 17 passes, but it
  depends on `import.meta.env` being read at runtime rather than inlined by
  Vite; if a future Vite release inlines statically, that test may need to move
  to a build-level check.
* **Real-data evaluation is still absent.** `backend/eval/data/` does not exist
  (git-ignored), so no real-dataset metrics exist. No accuracy claim is made for
  phishing detection in the real world; the risk score is a heuristic.
* **Deployment templates remain unvalidated.** No `nginx`, `caddy`, `docker`,
  `openssl` or `sqlite3` binary is available, and `systemd` is Linux-only, so
  `deploy/` is still documentation-grade only.
* **No version control.** This directory is not a Git repository, so there is no
  diff, commit or stash; the table in §6 is the record of what changed.

---

## 11. Day 18 priorities

1. Decide the history-authentication question (H-1). Either add a minimal
   documented gate or state explicitly in the README that the endpoints are
   intentionally open for a loopback-only demo.
2. Convert the manual integration checks in §8 into a repeatable script so they
   are no longer hand-run.
3. Optionally widen frontend tests to component rendering — this would require
   a DOM environment (`jsdom`/`happy-dom`) and needs separate approval.
4. Consider a visible "local demo — loopback only" banner in the UI so the
   security posture is visible to a demo audience.
5. Ensure `backend/phisguard.db` (and any `ops/` backup) is excluded from any
   artefact handed to a grader.

---

## 12. Command traceability

| # | Command (working directory) | Exit | Observed |
| --- | --- | --- | --- |
| 1 | `npm install --dry-run vitest@5.0.5` (frontend) | 0 | 18 adds, 0 change/remove, no peer warning |
| 2 | `Get-FileHash package.json / package-lock.json` | 0 | hashes unchanged by the dry run |
| 3 | `npm install --save-dev vitest@5.0.5` (frontend) | 0 | 18 packages, 0 vulnerabilities |
| 4 | `npm ls vite` (frontend) | 0 | single `vite@8.3.4`, deduped |
| 5 | `npm test` (frontend) | 0 | 17 passed / 1 file |
| 6 | `npm run lint` (frontend) | 0 | 0 problems |
| 7 | `npm run build` (frontend) | 2 then 0 | first run hit TS2352 in the test helper; fixed; then 35 modules |
| 8 | `pytest -q` (backend) | 0 | 331 passed, 1 warning |
| 9 | `pytest tests/test_deploy_artifacts.py -q` (backend) | 0 | 36 passed |
| 10 | `npx vite --host 127.0.0.1 --port 5199 --strictPort` | teardown 1 | bound `127.0.0.1` only, no `0.0.0.0` |
| 11 | `npx vite --port 5198 --strictPort` | teardown 1 | bound `::1` only (previous behaviour) |
| 12 | `npm run dev` (frontend) | teardown 1 | `Local: http://127.0.0.1:5173/` |
| 13 | `uvicorn app.main:app --reload --host 127.0.0.1` (backend, temp DB) | teardown 1 | bound `127.0.0.1:8000` only |
| 14 | `Invoke-WebRequest` / `curl.exe` against both servers | 0 | see §8.2–8.4 |
| 15 | Browser open/fill/click/evaluate/network/console | n/a | `/result/3`, Medium 25/100, clean console |

---

*End of Day 17 report. No dependency other than Vitest was added; no file other
than those listed in §6 was modified.*
