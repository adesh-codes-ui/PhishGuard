# Day 21 — Final project readiness review

**Date:** 2026-10-19
**Scope:** local-only college demonstration. This is a **review**, not a feature
day. Nothing here claims PhishGuard is production-ready, has passed a security
audit, or detects real-world phishing at any measured accuracy.
**Previous reports:** `DAY6`–`DAY12`, `DAY15`–`DAY20`. This file is new; no
earlier report was modified or overwritten.

---

## 1. Summary

| Phase | Outcome |
| --- | --- |
| 1 — Verify | Repository, scripts, startup commands, bind addresses, E2E isolation/cleanup and README claims inspected directly. **Four documentation defects found** (§4); no code defect found. |
| 2 — Validate | Full suite re-run on the final tree: **331** backend / **36** deploy / **35** frontend / **18** E2E, lint 0, build 0 — all exit 0. |
| 3 — Limitations | Every required limitation is documented accurately; one wording gap fixed (cleartext storage made explicit). |
| 4 — Report | This file. |

**Bottom line: the project is ready for a local demo and for an interview
presentation, within the documented local-only scope.** The only changes made
were **documentation** (two Markdown files) plus this report. No source, test,
dependency, lockfile or configuration file was touched. No dependency was added.
No scoring threshold or API contract was changed.

---

## 2. Starting state (re-measured, not assumed)

| Item | Value (observed this session) |
| --- | --- |
| Node.js / npm | 24.17.0 / 11.13.0 |
| Vite / Vitest / TypeScript / Oxlint | 8.3.4 / 5.0.5 / 6.0.3 / 1.88.0 |
| React / react-dom / react-router-dom | 19.2.8 / 19.2.8 / 7.18.4 |
| Python / pytest / uvicorn / FastAPI | 3.12.10 / 8.4.2 / 0.54.0 / 0.143.3 |
| `frontend/.env`, `backend/.env` | both **absent** (only `.env.example`) → built-in defaults apply |
| Git repository | **still none**; all changes exist on disk only, nothing committed |
| `backend/phisguard.db` | present, 24,576 bytes, mtime `2026-10-18 12:15:58` (unchanged all session) |

---

## 3. Phase 1 — Verification of the current project

| # | Check | Result |
| --- | --- | --- |
| 1 | Repository and current scripts inspected | **Pass.** `frontend/package.json` scripts: `dev`, `build` (`tsc -b && vite build`), `lint`, `test` (`vitest run`), `test:watch`, `test:e2e`, `preview`. E2E script present at `scripts/e2e-smoke.mjs`. `README.md`, `deploy/README.md`, `backend/ops/README.md`, `frontend/vite.config.ts`, `backend/app/config.py`, `backend/tests/*` read directly. |
| 2 | Documented local startup commands correct | **Pass.** Backend: `python -m venv .venv`, `pip install -r requirements.txt`, `python -m uvicorn app.main:app --reload --host 127.0.0.1`. Frontend: `npm install`, `npm run dev`. These match what was actually exercised (uvicorn on `127.0.0.1:8000`, Vite on `127.0.0.1:5173`). |
| 3 | Frontend and backend bind to `127.0.0.1` | **Pass.** `frontend/vite.config.ts:19` sets `server.host: '127.0.0.1'`, `port: 5173`; the backend is documented (and was run) with `--host 127.0.0.1`. CORS default is `http://localhost:5173,http://127.0.0.1:5173` (`config.py:54`). |
| 4 | E2E script uses isolated temp data and cleans up | **Pass.** It always sets a child `PHISHGUARD_DATABASE_PATH` inside a fresh `%TEMP%/phisguard-e2e-*` directory, strips `VIRUSTOTAL_API_KEY`, and tears down in a `finally` block plus signal handlers. After this session's run: **no leftover temp directories, no stray `python`/`node` processes, no listeners**, and `backend/phisguard.db` untouched. |
| 5 | Main frontend, backend and E2E commands documented | **Fail → fixed.** Frontend and backend were documented; the **E2E command was not documented anywhere in the README** (defect D21-1, §4). Fixed. |
| 6 | README unsupported security/accuracy claims | **Pass.** Every mention of safety/accuracy is explicitly *negative or conditional* ("Not a safety guarantee", "not that the URL is safe", "Real-world detection accuracy has not been established", "Nothing here is claimed to be safe to expose"). No production-readiness, audit, or detection-rate claim was found. |

No code, test, dependency or configuration defect was found. The application is
unauthenticated by design (Day 19 decision) and that is consistent across the
docs.

---

## 4. Defects found and changes made

All four defects are **documentation-only**. Two files changed:
`README.md` (4 edits) and `frontend/README.md` (replaced). No dependency was
added; no scoring threshold or API contract changed.

| ID | Severity | Defect | Fix |
| --- | --- | --- | --- |
| **D21-1** | Medium | The Day 20 E2E smoke test (`npm run test:e2e`) was **not documented** in `README.md`, so the third test layer was undiscoverable. Phase 1 item 5 requires it. | Added an **"End-to-end smoke test"** subsection to README §3 with the exact commands, the build prerequisite, and what it does/does not cover. |
| **D21-2** | Low | The README project-structure tree did not list the new `scripts/` directory. | Added `scripts/e2e-smoke.mjs` to the tree. |
| **D21-3** | Low | The structure comment still said `DAY6..DAY19`, stale after Day 20 (and now Day 21). | Updated to `DAY6..DAY21` (the same maintenance the project performed on Days 16/18/19). |
| **D21-4** | Low | `frontend/README.md` was the **unmodified Vite template** ("This template provides a minimal setup…", advice to install `oxlint-tsgolint` for "a production application"). Misleading in a final deliverable. | Replaced with a short, accurate frontend README (scripts, `VITE_API_BASE_URL`, testing notes, local-only scope, link to the root README). |

Additional wording improvement (part of Phase 3): the cleartext-storage
statement was made explicit in README §"Deployment and data lifecycle" (§6.3).

**Risk assessment of the changes:** Markdown only. The only automated assertions
touching these files are in `backend/tests/test_deploy_artifacts.py`, and they
were **re-run after every edit** and still pass (§5). The pinned strings
(`uvicorn app.main:app --reload`, `npm run dev`, `ops/db_lifecycle.py` in the
root README; `unauthenticated`, `no user model`, `does not make a publicly
reachable, unauthenticated API safe`, `was executed or validated on a real
host`, `no nginx` in `deploy/README.md`) were preserved.

---

## 5. Phase 2 — Validation (run on the final tree)

All commands were run in this session, after the documentation edits. Exit codes
are the actual observed values.

| Check | Command | Result | Exit |
| --- | --- | --- | --- |
| Backend suite | `.\.venv\Scripts\python.exe -m pytest -q` (in `backend/`) | **331 passed**, 1 warning, 5.34 s | 0 |
| Deployment artifacts | `.\.venv\Scripts\python.exe -m pytest tests/test_deploy_artifacts.py -q` | **36 passed**, 0.19 s (re-run after the final README edit) | 0 |
| Frontend suite | `npm test` (`vitest run`) | **3 files / 35 tests passed**, 3.86 s | 0 |
| Lint | `npm run lint` (`oxlint`) | **0 problems** | 0 |
| Type-check + build | `npm run build` (`tsc -b && vite build`) | 35 modules; `index-DQmeeZmu.css` 29.77 kB (5.92 kB gzip); `index-DW3KsOvZ.js` 278.68 kB (87.66 kB gzip); 266 ms | 0 |
| End-to-end smoke test | `npm run test:e2e` (in `frontend/`) | **18 passed, 0 failed, 0 skipped** (ports 49257/49258) | 0 |

The production bundle hashes are **unchanged** from the Day 19/20 baseline — as
expected, because no source or style file changed in this session.

### 5.1 Warning (unchanged, third-party)

```
backend\.venv\Lib\site-packages\fastapi\testclient.py:1
  StarletteDeprecationWarning: Using `httpx` with `starlette.testclient`
  is deprecated; install `httpx2` instead.
```

Present before and after; not caused by any Day 21 change.

### 5.2 Cleanup / isolation re-verified

After the E2E run: no `phisguard-e2e-*` temp directories, no stray `python`/`node`
processes, no listeners on the used ports, and `backend/phisguard.db` still
24,576 bytes with mtime `2026-10-18 12:15:58`.

---

## 6. Phase 3 — Known limitations are documented accurately

| Required limitation | Where it is documented | Status |
| --- | --- | --- |
| **Unauthenticated history endpoints** | README "Scope" (line 28), API table (both history routes marked **unauthenticated**), the data-lifecycle blockquote, and "Known limitations"; `deploy/README.md` §"History access: the largest deployment risk" | **Accurate.** |
| **Local-only usage and loopback binding** | README "Scope: local-only demo" (backend `--host 127.0.0.1`, `vite.config.ts` `server.host`, CORS allow-list), §1 and §2 | **Accurate.** |
| **Cleartext URL storage** | `backend/ops/README.md` "Privacy" (stores raw + normalized URL; readable by anyone with filesystem/backup/`GET /api/history` access); README data-lifecycle now states it **in cleartext** with no at-rest encryption | **Accurate** (wording strengthened by D21-1 follow-up). |
| **Lack of real-world detection accuracy evaluation** | README "Known limitations": accuracy/precision/recall describe only the 12-case synthetic fixture set, explicitly "**not** a real-world detection rate"; `backend/eval/data/` does not exist | **Accurate.** |
| **Unvalidated deployment templates** | README "Deployment and data lifecycle" ("reviewed examples, **not validated** artifacts"); `deploy/README.md` header ("Nothing in this directory was executed or validated on a real host") | **Accurate.** |
| **Automated E2E smoke test vs manual browser verification** | README §3 "End-to-end smoke test" (says it "does not replace the manual browser check"); `backend/eval/DAY20_REPORT.md` §7.3 distinguishes the automated checks from the manual Chromium pass | **Accurate.** |

No documentation claim was found that overstates safety, deployment readiness,
or detection accuracy.

---

## 7. Remaining limitations (unchanged, stated plainly)

- **No authentication anywhere** (`/api/analyze`, `/api/history`, `/api/history/{id}`,
  `/api/health`). Accepted *only* while the service is bound to loopback; the
  loopback bind is the sole access control. There is no automated guard against a
  non-loopback bind, by design.
- **CORS is not a security boundary** — browser-enforced only.
- **No TLS of its own**; loopback traffic to uvicorn is cleartext HTTP.
- **The SQLite file stores analyzed URLs in cleartext**, with no retention policy
  and no automatic deletion; `ops/` backups are likewise cleartext until handled.
- **`backend/phisguard.db` may contain URLs typed during manual testing** and
  must be kept out of anything handed to a grader, along with `ops/` backups.
- **Deployment templates are unvalidated** (`nginx`, `caddy`, `docker`, `openssl`,
  `sqlite3` absent on this machine; systemd is Linux-only).
- **Real-world detection accuracy has never been established.**
- **The E2E smoke test is not a browser.** It does not execute the React bundle,
  so the rendered DOM and browser CORS enforcement remain covered by the jsdom
  suite (stubbed) plus a manual browser pass that is not grader-repeatable.
- No DOM-level accessibility audit and no code-coverage reporting.

---

## 8. Local-demo readiness decision

**READY for a reliable local demo and interview presentation**, within the
documented local-only scope. Evidence:

1. **Three complementary, green test layers** — unit/component (35 frontend),
   API/contract (331 backend + 36 deployment/doc), and **live end-to-end**
   (18 checks against real processes and real HTTP), all exit 0.
2. **The E2E command is now documented**, so a reviewer can reproduce the live
   seam with `npm run build && npm run test:e2e`.
3. **Isolation and cleanup are proven** and leave no residue and no changes to
   the developer's database.
4. **Documentation is honest**: every required limitation is stated, and no claim
   exceeds what the code does.

Not ready for, and not intended for, any networked or public exposure.

---

## 9. Claim boundary

Every command, exit code, test count and byte size in this report was observed in
this session; anything not run is stated as not run. Historical results from
Days 18–20 were treated as historical and re-measured rather than quoted.

This report does **not** claim: production readiness; that a security audit was
performed; that CORS provides access control; that the documentation changes make
a non-loopback deployment safe; or that PhishGuard detects real-world phishing
with any measured accuracy.

---

## 10. Final status and recommended next step

**Final status:** PhishGuard is a complete, self-consistent, honestly-documented
local-only demo with 420 automated checks green (331 + 36 + 35 + 18), a clean
build, and no outstanding code defect. Day 21 changed **documentation only**.

**Recommended next step:** before the interview, rehearse the demo with a
**throwaway database** (e.g. `PHISHGUARD_DATABASE_PATH` pointing at a temp file,
or `node scripts/e2e-smoke.mjs` as a dry run) so no previously pasted URLs appear
on screen, and keep `backend/phisguard.db` and any `ops/` backups out of the
handed-over artefact. If a real-data accuracy evaluation is ever wanted, that is
a new, separate task requiring an external dataset — not a change to this demo.
