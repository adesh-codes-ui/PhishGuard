# Day 10: API Security Hardening

**Scope:** local static review of the API surface plus targeted hardening. This
is **not a penetration test** — no fuzzing, no load testing, no external
scanning, no network probing of the service. Findings below are backed by code
reading and executable tests (ASGI-level and against a real uvicorn process).

**Baseline:** 195 tests passed (Day 9). **After:** 207 passed, 1 warning.

Unchanged by design: heuristic scoring, production bands (Low 0-24 / Medium
25-49 / High 50-74 / Critical 75-100, `app/analyzer.py:339-345`), the success
response contract, `requirements.txt` (no new dependency), and the Day 9
dataset-evaluation status (still blocked: no real dataset present).

## 1. What was audited

`app/main.py`, `app/config.py`, `app/schemas.py`, `app/database.py`,
`app/providers/virustotal.py`, `app/analyzer.py` (entry points only),
`tests/test_api.py`, `tests/test_virustotal.py`, `frontend/src/api/client.ts`,
`.env.example`, `README.md` run instructions.

## 2. Findings, prioritized

### P1-a — No request-body size limit (fixed)

**Evidence:** Starlette/FastAPI impose no request-body limit by default, and the
JSON body is parsed *before* Pydantic validates it. Before this change an
oversized body (e.g. 20 KiB of `{"url": "xxx…"}`) was fully read and parsed; only
afterwards did validation return 422. A client could therefore push arbitrarily
large bodies into memory. Nothing in the middleware stack limited size.

**Fix:** `app/security.py::BodySizeLimitMiddleware` (registered in `main.py`):

- declared `Content-Length` above the limit -> immediate HTTP 413, body not read;
* a malformed `Content-Length` -> 400;
* bodies without/lying about `Content-Length` are counted while streaming and
  cut off mid-stream (`413`).

Default limit 16 KiB (`PHISHGUARD_MAX_REQUEST_BODY_BYTES`), deliberately ~8x the
largest legitimate payload (a 2048-character URL plus JSON overhead).
Error body keeps the frontend's expected shape: `{"detail": "..."}`.

**Status:** fixed, tested at ASGI level and against real uvicorn.

### 1.1 URL length and malformed input (verified, no change needed)

Already enforced in two layers, now locked in by tests:

- `AnalyzeRequest.url`: `min_length=1`, `max_length=2048` → HTTP 422;
- `analyzer.normalize_url`: `MAX_URL_LENGTH = 2048` → `InvalidURLError` → HTTP 400;
  plus control-character, whitespace, empty-label, invalid-label and
  scheme checks (only `http`/`https` accepted → 400).
- Malformed IPv6 (`http://[::1`) returns 400, not a raw 500 (existing regression
  test `test_analyze_unclosed_ipv6_returns_400_not_500`).

### 1.2 Unauthenticated history exposure (P1 risk, deliberately NOT changed)

`GET /api/history` and `/api/history/{id}` return every stored scan (URL,
normalized URL, host, score, findings) to any client that can reach the service.
`POST /api/analyze` is also unauthenticated.

Not changed, because the current architecture has no user/account model, is a
single-user local MVP, and adding auth would change the API contract and the
frontend. Deployment mitigation instead: bind the service to localhost, or place
it behind an authenticating reverse proxy / API gateway. This is the **top
residual risk** (see §5).

### 2.1 Rate limiting (implemented, opt-in)

**Finding:** no rate limiting existed anywhere; `/api/analyze` is unauthenticated
compute, and each call also writes a row and may trigger a VirusTotal lookup.

**Change:** optional `RateLimitMiddleware` (default **off**):

- fixed 60 s window, 60 requests per client by default, all configurable;
- keys on the directly connected peer address (`scope["client"]`).
  `X-Forwarded-For` is deliberately **not trusted** (it is client-controlled;
  blindly trusting it would let one host bypass the limit by rotating the header);
- `/api/health` and CORS preflights are never limited;
- excess traffic → HTTP 429 + `Retry-After`, body `{"detail": "..."}`.

**Honest limitation (documented in code, config, `.env.example` and here):** the
counter is **in-process memory only**. With `uvicorn --workers N` each worker has
its own counter, so the effective allowance is `N x rate_limit_requests`; a
distributed deployment gets no shared limit at all, and counters reset on
restart. This is best-effort abuse mitigation, **not** a security boundary. Real
protection belongs in a reverse proxy / API gateway / shared store in front of
the service. Because the default is "off", deployment behavior is unchanged
unless the operator opts in.

### 1.3 Error handling and information disclosure (fixed)

Before: unhandled exceptions produced Starlette's default plain-text
`Internal Server Error` (no traceback leaked — good) and database failures were
indistinguishable from bugs; no server-side logging boundary was defined.

After (`app/main.py`):

- `sqlite3.Error` → **503** `{"detail": "Scan history is temporarily unavailable."}`
- any other exception → **500** `{"detail": "Internal server error."}`
- full diagnostics (method, path, traceback) go to the server log via
  `logger.exception` and never into the response.

Tests assert that exception types, file paths, table names and a
secret-looking token cannot appear in the body.

Kept as-is: FastAPI's 422 validation body (the frontend parses
`detail[0].msg`); its echoed input/field metadata is now bounded by the new body
limit.

### 1.4 CORS (verified, no change)

Defaults are developer-local only:
`http://localhost:5173,http://127.0.0.1:5173`, `allow_credentials=False`,
`allow_methods=["GET", "POST"]`, no wildcard. Tests now pin: the default never
contains `*`, a listed origin receives `Access-Control-Allow-Origin`, and an
unlisted origin receives no such header. Middleware ordering is deliberate: CORS
is outermost so browsers can read the hardening middlewares' 413/429 bodies
(asserted by a test).

### 1.5 SQLite query safety and history behavior (verified, no change)

- Every statement uses `?` placeholders; user input is never interpolated. The
  only f-strings in SQL are internal migration constants (`_MIGRATIONS`).
- `limit` is validated by FastAPI (`ge=1, le=100`) and coerced with `int()`;
  `scan_id` is a typed path parameter; unknown ids → 404.
- `findings` are stored/returned as JSON text only; a SQL-injection-style payload
  in the URL is stored inertly (existing test `test_findings_are_json_safe`).

Remaining behaviors now documented as risks rather than changed: unbounded row
growth (no retention), single-writer locking under concurrency (now surfaced as
503 instead of a stack trace), and no encryption at rest.

### 1.6 VirusTotal timeout and failure handling (verified, no change)

Every failure mode is contained and mapped (never raises into the request):

| Condition | Result |
|---|---|
| no key / disabled | `status=disabled`, `verdict=unavailable` |
| timeout | `status=timeout` (message includes the configured seconds) |
| connection/HTTP error | `status=error` (exception type name only) |
| 401 / 403 | `status=invalid_key` |
| 429 | `status=rate_limited` (+ provider `Retry-After`) |
| 5xx / other non-200 | `status=error` |
| malformed JSON body | `status=error` |

Also verified: the provider only looks up an **existing** report
(`GET /urls/{id}`, where `{id}` is `base64url(sha256(url))`) — it never submits
the URL for scanning; the API key is read from `VIRUSTOTAL_API_KEY` only, is
never logged and never serialized into a response; threat intel is stored and
returned separately and cannot change `risk_score`/`risk_label` (existing tests).
Timeout is configurable and defaults to 10 s.

Remaining: the lookup is synchronous, so `/api/analyze` latency can grow by up
to the timeout when a key is configured; the provider response body is not
size-capped; `PHISHGUARD_VIRUSTOTAL_BASE_URL` is operator-controlled and could be
pointed at an internal host if the environment is compromised.

## 2. Changes made

| File | Change |
|---|---|
| `backend/app/security.py` | **new** — pure-ASGI `BodySizeLimitMiddleware`, opt-in `RateLimitMiddleware`, `SecurityHeadersMiddleware` (`X-Content-Type-Options: nosniff`), `client_identifier` |
| `backend/app/main.py` | registers the three middlewares (CORS last/outermost, with an explanatory comment), adds the `sqlite3.Error`→503 and `Exception`→500 handlers with server-side logging, docstring note |
| `backend/app/config.py` | `max_request_body_bytes=16384`, `rate_limit_enabled=False`, `rate_limit_requests=60`, `rate_limit_window_seconds=60` |
| `backend/.env.example` | documents the four new variables and the per-process caveat |
| `backend/tests/test_security.py` | **new** — 12 regression tests (body limit incl. streamed path, URL-length contract, limiter on/off + health exemption, 503/500 non-leak, security header, CORS default and preflight) |
| `backend/eval/DAY10_REPORT.md` | **new** — this report |

Not changed: analyzer, scoring weights, production bands, schemas, database
queries, provider code, frontend, `requirements.txt`.

## 3. Verification and evidence

- Backend: **207 passed, 1 warning, 0 failures** in the canonical `.venv`
  (195 baseline + 12 new; the warning is the pre-existing Starlette `httpx2`
  deprecation notice).
- Frontend production build: **succeeded** (`tsc -b && vite build`, 35 modules,
  `index-*.js` 278.50 kB) — no frontend change was needed because error bodies
  keep the `detail` shape.
- Real uvicorn process (`--port 8019`, limiter enabled at 3 req/60 s), observed:

```
1 health                 -> 200 (exempt)
2 analyze (hit 1)        -> 200 Low
3 oversized body (hit 2) -> 413 {'detail': 'Request body is too large (max 16384 bytes).'}
4 history (hit 3)        -> 200
5 history (hit 4)        -> 429 retry-after=60 {'detail': 'Rate limit exceeded. Try again later.'}
6 health after limit     -> 200 (exempt)
7 x-content-type-options -> nosniff
8 cors preflight         -> 200 allow-origin=http://localhost:5173
9 unknown scan (hit 5)   -> 429 (limiter still tripped; the unchanged 404
                            contract for a missing scan id is covered by
                            test_history_detail_not_found)
```

- Production safety: `app/analyzer.py` unmodified (mtime 18 Oct, bands still
  75/50/25); `requirements.txt` unmodified (no new dependency); no authentication
  code added (no `Depends(...)`/OAuth/JWT scaffolding).

## 4. Remaining deployment risks (all open)

1. **No authentication/authorization.** Anyone who can reach the service can
   analyze URLs and read the full scan history. Highest-priority gap; mitigate by
   binding to `127.0.0.1` and/or fronting with an authenticating proxy.
2. **Rate limiting is per process and off by default.** Multi-worker and
   distributed deployments are not protected; the limiter does not survive
   restarts. Do not treat it as a boundary.
3. **Client identity behind a proxy.** The limiter keys on the directly connected
   peer; `X-Forwarded-For` is deliberately not trusted. Behind a proxy without
   proxy-level limiting, all clients share one bucket.
4. **No TLS in the app.** Terminate TLS at the reverse proxy; the dev server is
   plain HTTP.
5. **Docs exposed by default** (`/docs`, `/redoc`, `/openapi.json`). Restrict or
   block at the proxy in production.
6. **Unbounded SQLite growth** from `/api/analyze`; no retention job, no WAL
   configuration, no encryption at rest. Concurrent writes can hit
   "database is locked" (now a 503, not a leak).
7. **No application-level request timeout or concurrency cap.** `uvicorn
   --limit-concurrency` / proxy timeouts are the available controls.
8. **VirusTotal adds latency** (up to the configured timeout) to `/api/analyze`
   when a key is present; its response body is not size-capped. Optional feature,
   off without a key.
9. **Body limit lives in the app.** Keep a proxy-level body limit too, as
   defence in depth (e.g. nginx `client_max_body_size`).

## 5. Explicit non-claims

- No penetration test, fuzzing, load test or third-party scan was performed.
- The in-memory limiter is not claimed to protect multiple workers, multiple
  hosts or a distributed deployment.
- No production scoring threshold, weight, API success contract or UI behavior
  was changed.
- Day 9's dataset evaluation remains **blocked**: no real PhishTank/Tranco data
  is present locally, so the reported status is unchanged.
