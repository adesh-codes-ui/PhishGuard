# Day 19 — Security Decision and Final Local-Scope Review

**Date:** 2026-10-19
**Scope:** local-only college demonstration. Nothing in this report claims that
PhishGuard is safe for public deployment, has passed a security audit, or
detects real-world phishing at any particular accuracy.
**Previous reports:** `DAY6`–`DAY12`, `DAY15`, `DAY16`, `DAY17`, `DAY18`. This
file is new; no earlier report was modified or overwritten.

---

## 1. Summary

| Phase | Outcome |
| --- | --- |
| 1 — Investigate | Read the real implementations of `/api/history`, `/api/history/{id}`, the database access layer, the frontend consumers, and the bind/CORS configuration. Confirmed the endpoints are unauthenticated **in code**, not just in documentation. No source was modified. |
| 2 — Recommend | Compared three options (A: keep local-only + document; B: add authentication/authorization; C: another mitigation). **Recommended and took Option A** — the smallest safe option consistent with the existing local-demo scope. |
| 3 — Implement | **Documentation only.** 4 edits to `README.md`, 2 edits to `deploy/README.md`. **No source code, no tests, no dependencies, no configuration changed.** Auth was explicitly **not** added. |
| 4 — Validate | Baseline re-measured, then full re-run after the edits: **331** backend / **36** deploy / **35** frontend, lint 0, build 0, identical bundle hashes. |
| 5 — Report | This file. |

**Bottom line:** the H-1 finding (unauthenticated history API) is now an
**explicitly accepted, conditional limitation of a loopback-only demo**, not an
open question. No code change was required; the loopback bind is — and is
documented as — the only access control. The local demo remains ready.

---

## 2. Method and starting state

The Day 18 report and the current tree were treated as historical until
re-measured. Before any edit was made, every validation command was re-run.

| Check | Result |
| --- | --- |
| Git repository | **still none** — `git rev-parse --is-inside-work-tree` → `fatal: not a git repository`, exit **128**. All changes exist on disk only. |
| `frontend/.env`, `backend/.env` | both **absent** (only `.env.example`), so the built-in defaults apply |
| `PHISHGUARD_CORS_ORIGINS` in effect | `http://localhost:5173,http://127.0.0.1:5173` (the default) |

The reported Day 18 baseline reproduced exactly. See §6 for the numbers.

---

## 3. Phase 1 — Investigation (evidence, no changes)

### 3.1 Route implementations (`backend/app/main.py`)

| Route | Lines | Handler | Authentication |
| --- | --- | --- | --- |
| `GET /api/history` | 217–237 | `history(limit=Query(50, ge=1, le=_settings.history_limit))` → `list_scans()` + `count_scans()` | **none** |
| `GET /api/history/{scan_id}` | 240–264 | `history_detail(scan_id)` → `get_scan()`, `404` if absent | **none** |

There is no authentication anywhere in the request path:

- Neither route takes a FastAPI dependency (`Depends(...)`); neither accepts a
  credential of any kind.
- `FastAPI(...)` (lines 101–110) registers **no** security scheme — no
  `OAuth2`, no `HTTPBearer`, no API-key header.
- The middleware stack (lines 115–132) is only: `BodySizeLimitMiddleware` →
  `RateLimitMiddleware` (disabled by default) → `SecurityHeadersMiddleware` →
  `CORSMiddleware`. The sole security-relevant header added is
  `X-Content-Type-Options: nosniff`. Nothing inspects the caller's identity.

### 3.2 Database access (`backend/app/database.py`)

- `list_scans()` (130–143) and `get_scan()` (146–158) use **parameterized
  queries** — so the finding is not an injection issue. `get_scan(scan_id)`
  fetches by id **alone**.
- The schema (lines 19–33) has **no owner / tenant / user column**. There is no
  concept of "whose scan" in storage, so per-user isolation does not exist even
  implicitly.
- `id INTEGER PRIMARY KEY AUTOINCREMENT` → ids are small sequential integers,
  i.e. trivially enumerable.
- `count_scans()` (161–165) is exposed unauthenticated via `/api/health`.

### 3.3 What the history endpoints actually expose

| Endpoint | Fields returned |
| --- | --- |
| `GET /api/history` | For **every** stored scan: `id`, `url` (the **exact submitted string** — including any tokens/secrets in a query string), `normalized_url`, `host`, `risk_score`, `risk_label`, `created_at`; plus `total`. The list deliberately omits findings (pinned by `test_history_list_stays_lightweight`). |
| `GET /api/history/{id}` | Adds `scheme`, `registrable_domain`, `findings[]`, and the stored `threat_intel` snapshot. |
| `GET /api/health` | `status`, `version`, `scans_stored` (a count). |
| `POST /api/analyze` | Unauthenticated too, so anyone who can reach the port can spend CPU (and VirusTotal quota, if a key is configured). |

`GET /api/history?limit=` is capped at `PHISHGUARD_HISTORY_LIMIT` (default 100),
but the `total` count and sequential ids make full enumeration possible
regardless.

### 3.4 How the frontend uses these endpoints

- `frontend/src/pages/Dashboard.tsx:37` calls `getHistory(15)` on mount;
  `HistoryList` renders **host + time + risk badge**, each linking to
  `/result/:id`.
- `frontend/src/pages/ResultPage.tsx` calls `getScan(id)` and renders the
  **full submitted URL** in the "Submitted" row, plus normalized URL, scheme,
  host, registrable domain, findings and the threat-intel panel.
- `frontend/src/api/client.ts` (148–161) issues plain `fetch` calls with only a
  `Content-Type: application/json` header — **no** credentials, tokens, cookies
  or authorization header. Adding application auth would require changing the
  client and both pages.

### 3.5 Bind addresses and CORS (verified, not assumed)

| Component | Setting | Evidence |
| --- | --- | --- |
| Backend bind | `--host 127.0.0.1` | documented command, `README.md` §1 |
| Frontend bind | `server.host = '127.0.0.1'`, port 5173 | `frontend/vite.config.ts:19` |
| CORS origins | `http://localhost:5173`, `http://127.0.0.1:5173` | `backend/app/config.py:54` |
| `allow_credentials` | `False` | `backend/app/main.py:129` |
| Wildcard in production | refused at startup | `config.py:129–133` |

**CORS is not access control.** It is enforced by browsers only; a direct HTTP
client (`curl`, a script, another service) ignores the origin list entirely and
is unaffected by it. The **loopback bind is the only thing** that limits who can
reach the port.

---

## 4. Phase 2 — Decision

### 4.1 Options compared

| Option | Benefits | Risks | Implementation cost |
| --- | --- | --- | --- |
| **A. Keep the app strictly local-only and document the limitation** | Zero code/dependency change; preserves the project's scope exactly; matches reality (the loopback bind is the only control that exists); no regression risk to scoring, contracts or tests; honest. | H-1 remains. If anyone starts uvicorn with `--host 0.0.0.0`, forwards the port, publishes a container port, or fronts it with a proxy without auth, the full URL history is exposed. The mitigation is documentation-dependent. | Low — documentation edits + re-running the documentation tests. |
| **B. Add authentication and authorization** | Actually closes H-1; would enable shared/networked use. | Large, explicit scope expansion: user model, ownership, credential storage, sessions/tokens, CSRF and rate-limit interaction, a login UI, contract changes in `client.ts` and both pages, and new backend + frontend tests. Nothing in storage records ownership today (§3.2), so it is a schema change too. A demo-grade auth layer would add its own security-sensitive surface that itself needs review — and risks over-selling safety. | High (days); changes the API contract and the frontend. |
| **C. Another proportionate mitigation** | Cheaper than B. | The two obvious candidates do not actually help: (1) extending the existing wildcard-CORS refusal from production to development is **security theatre**, because CORS is not a boundary and does not protect the history endpoints; (2) a startup guard that "detects a non-loopback bind" is unreliable — an ASGI app cannot see uvicorn's `--host`, so a partial env/argv check would be brittle and could give false confidence. | Low but ineffective. |

### 4.2 Recommendation taken: **Option A**

The smallest safe option consistent with the local-demo scope is to **keep the
app strictly local-only and record the decision honestly**. Concretely:

- the unauthenticated history API is **accepted** as a property of the project
  **because and only because** the service is bound to loopback, where the only
  possible client is the same machine/user;
- that acceptance is **conditional** and lapses the moment the API is reachable
  from another machine, at which point authentication (proxy-side or in-app) or
  a private network/VPN becomes mandatory;
- application authentication remains a **future product decision**, not an
  implemented feature.

This is a decision about an accepted risk, not a claim that the risk is gone.
Option B was **not** taken because it silently broadens a local demo into an
authenticated multi-user system, which the brief explicitly forbids.

> Note on process: a review prompt was raised to confirm the direction before
> implementing. It was not answered, so the **recommended** (and smallest) option
> was implemented. No source code was touched as a result.

---

## 5. Phase 3 — Implementation (documentation only)

### 5.1 Files changed

| File | Edits | Nature |
| --- | --- | --- |
| `README.md` | 4 | Documentation |
| `deploy/README.md` | 2 | Documentation |

**No source file, test file, dependency manifest, lockfile or configuration file
was changed.** `backend/app/*`, `frontend/src/*`, `vite.config.ts`,
`package.json`, `requirements.txt` and the `.env.example` files are untouched.

### 5.2 `README.md` — what changed and why

1. **Scope: local-only demo** — added a **"Decision (Day 19)"** paragraph after
   the existing "not safe to expose" statement. It records that the open history
   API is accepted *because of the loopback bind*, and lists the conditions that
   would void that acceptance (`--host 0.0.0.0`, port-forwarding, published
   container port, proxy), requiring authentication first. It points to
   `DAY16_REPORT.md` (H-1) and this report.
2. **Deployment and data lifecycle** blockquote — the final sentence previously
   said adding application authentication was "an unresolved product decision".
   It now records the local-demo decision, keeps the "does **not** make a
   publicly reachable, unauthenticated API safe" warning, and states that
   exposing the service beyond loopback requires authentication first.
3. **Known limitations** — the "No authentication on any endpoint" bullet was
   reframed from an open gap to an **accepted, documented limitation**, with the
   loopback-containment condition and a pointer to the scope section.
4. **Project structure** — the eval comment `DAY6..DAY18` → `DAY6..DAY19`, so the
   listing stays true now that this report exists.

### 5.3 `deploy/README.md` — what changed and why

1. Section heading `## History access: the largest unresolved risk` →
   `## History access: the largest deployment risk`. The finding is *resolved for
   the local demo* but remains the largest **deployment** risk — the new heading
   says exactly that.
2. The closing paragraph previously said "the decision itself is recorded as
   unresolved". It now records the **Day 19 conditional decision** and states
   that the moment the API is reachable from another machine, proxy-side (or
   in-app) authentication, or a private network/VPN, becomes mandatory. The
   finding history (Day 12 → H-1 Day 16 → decision Day 19) is linked.

The option table in that section (keep off the internet / authenticate at the
proxy / add app auth / disable history) is **unchanged** — it is still accurate.

### 5.4 What was deliberately **not** done

- No authentication, authorization, session, token, ownership or user model.
- No new endpoint, middleware, header or configuration setting.
- No change to CORS, bind addresses, scoring, weights or thresholds.
- No public deployment configured.
- No claim anywhere that CORS is an authentication mechanism.
- The pinned honesty strings in `deploy/README.md` were **preserved verbatim**:
  `no user model`, `does not make a publicly reachable, unauthenticated API
  safe`, `was executed or validated on a real host`, `no nginx`.

---

## 6. Phase 4 — Validation

### 6.1 Baseline (before any edit)

| Command | Result | Exit |
| --- | --- | --- |
| `python -m pytest -q` (backend) | `331 passed, 1 warning`, 5.79 s | **0** |
| `python -m pytest tests/test_deploy_artifacts.py -q` | `36 passed`, 0.23 s | **0** |
| `npm test` (`vitest run`) | `3 passed (3)` files / `35 passed (35)` tests, 4.59 s | **0** |
| `npm run lint` (`oxlint`) | 0 problems | **0** |
| `npm run build` (`tsc -b && vite build`) | 35 modules, `index-DQmeeZmu.css 29.77 kB / 5.92 kB gzip`, `index-DW3KsOvZ.js 278.68 kB / 87.66 kB gzip`, 288 ms | **0** |

### 6.2 After the documentation edits

| Command | Result | Exit |
| --- | --- | --- |
| `python -m pytest -q` (backend) | `331 passed, 1 warning`, 4.89 s | **0** |
| `python -m pytest tests/test_deploy_artifacts.py -q` | `36 passed`, 0.23 s | **0** |
| `npm test` (`vitest run`) | `3 passed (3)` / `35 passed (35)`, 2.91 s | **0** |
| `npm run lint` (`oxlint`) | 0 problems | **0** |
| `npm run build` (`tsc -b && vite build`) | 35 modules, `index-DQmeeZmu.css 29.77 kB / 5.92 kB`, `index-DW3KsOvZ.js 278.68 kB / 87.66 kB`, 247 ms | **0** |

The documentation change is asserted by tests, so it was validated after being
made: `test_deploy_artifacts.py` requires the root README to contain
`uvicorn app.main:app --reload`, `npm run dev` and `ops/db_lifecycle.py`, and
requires `deploy/README.md` to still contain `unauthenticated`, `no user model`,
`does not make a publicly reachable, unauthenticated API safe`. All 36 still pass.
A direct grep confirmed each pinned string is present in the edited files.

The production bundle is **byte-identical** to the Day 18 baseline (same content
hashes `index-DQmeeZmu.css` / `index-DW3KsOvZ.js` and sizes), which is expected:
no source or style file changed.

### 6.3 Warning (unchanged, third-party)

```
backend\.venv\Lib\site-packages\fastapi\testclient.py:1
  StarletteDeprecationWarning: Using `httpx` with `starlette.testclient`
  is deprecated; install `httpx2` instead.
```

Present before and after; not caused by this change.

---

## 7. Remaining risks

### 7.1 The accepted risk (H-1) — stated plainly

- `GET /api/history` and `GET /api/history/{id}` return every stored scan,
  including the exact submitted URLs, to **anyone who can reach the port**.
  Accepting it is only defensible while the port is reachable from this machine
  alone.
- The mitigation is the **loopback bind**, not anything in the application. It
  depends on the operator not overriding `--host`, not forwarding the port, and
  not publishing the container port.
- **There is no automated guard** that would fail if the service were started on
  a non-loopback address. A startup bind check cannot be done reliably from
  inside an ASGI app, and a partial env/argv check was rejected as brittle (§4.1).
  If a non-loopback bind is ever a real possibility, the correct next step is
  authentication, not a heuristic.
- `POST /api/analyze` is also unauthenticated (CPU/quota consumption) and
  `GET /api/health` leaks the stored-scan count.

### 7.2 Other limitations (unchanged)

- **CORS is not a security boundary** — browser-enforced only.
- **No TLS of its own**; traffic to uvicorn is cleartext HTTP on loopback.
- **Rate limiting is off by default and process-local.**
- **SQLite and `ops/` backups store URLs in cleartext**, with no retention
  policy and no automatic deletion.
- **`backend/phisguard.db` may contain URLs typed during manual testing** and
  should be excluded from any artefact handed to a grader, along with `ops/`
  backups.
- **Deployment templates remain unvalidated** (`nginx`, `caddy`, `docker`,
  `openssl`, `sqlite3` absent on this machine; systemd is Linux-only).
- **Real-world detection accuracy has never been established** — the only
  evaluation is a 12-case synthetic fixture set.

### 7.3 Testing gaps (unchanged)

- No end-to-end test against a live backend (process start, CORS preflight and
  SQLite persistence are still verified manually or by the backend suite).
- No DOM-level accessibility audit and no coverage reporting.

---

## 8. Does the local demo remain ready?

**Yes.** Nothing that the demo depends on changed:

- No source, test, dependency or configuration file was modified, so behaviour is
  identical to the verified Day 18 state.
- The full validation suite is green: **331** backend, **36** deploy /
  documentation, **35** frontend; lint 0; build 0; identical production bundle.
- The documentation now states the security position **more precisely** than
  before (an accepted, conditional limitation) without weakening any existing
  warning about public exposure.

The demo is ready for local demonstration on this machine. It remains **not**
ready for, and not intended for, any networked or public exposure.

---

## 9. Claim boundary

Every command, exit code, test count, byte size and content hash in this report
was observed in this session; anything not run is stated as not run. The exact
route line numbers, database behaviour and frontend call sites in §3 were read
from the files, not inferred from earlier reports.

This report does **not** claim: that PhishGuard is production-ready; that a
security audit was performed; that adding the documentation makes a
non-loopback deployment safe; that CORS provides any access control; or that
PhishGuard detects real-world phishing with any measured accuracy. It records a
**decision to accept** a known, documented, loopback-contained limitation.
