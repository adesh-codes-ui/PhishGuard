# PhishGuard 

A phishing-URL detection web application with an  0–100 risk
score. Paste a URL and PhishGuard inspects the URL *string* for common phishing
signals. It never visits, resolves, or fetches the submitted link.

> Not a safety guarantee. PhishGuard uses static heuristics. A low score
> means "no known red flags were found",  "this link is safe". Always
> verify a site through official channels before entering credentials.



PhishGuard is a local college project and demo. It is designed to run on a
single machine for a single user, bound to the loopback interface:

- The backend command in [1. Run the backend](#1-run-the-backend) passes
  `--host 127.0.0.1`, so uvicorn accepts connections only from the same machine.
- The Vite dev server sets `server.host` to the IPv4 loopback `127.0.0.1` in
  `frontend/vite.config.ts`, so it also listens on loopback only: reachable as
  `http://localhost:5173` and `http://127.0.0.1:5173`, never from another
  machine. (It binds IPv4 deliberately — `localhost` resolves to `::1` here,
  and binding that would leave `http://127.0.0.1:5173` unreachable even though
  CORS allow-lists it. See [2. Run the frontend](#2-run-the-frontend).)
- CORS is restricted to `http://localhost:5173` and `http://127.0.0.1:5173`.

**Nothing here is claimed to be safe to expose to a local network or to the
internet.** PhishGuard has no authentication, no TLS of its own, no per-user
data isolation, and its history endpoints are unauthenticated. Public
deployment is explicitly out of scope for this project; see
[Known limitations](#known-limitations) and [`deploy/README.md`](deploy/README.md)
for what would have to change first.

**Decision (Day 19).** The unauthenticated history API is an **accepted**
property of this project, and only because of the loopback bind above: the API
is designed to accept connections from the same machine only, so there is no
second party for it to authenticate. That acceptance is conditional — it holds
*only* while the service stays on loopback. If the API is ever bound past
loopback (`--host 0.0.0.0`), port-forwarded, published from a container, or put
behind a proxy, it must be authenticated first (at the proxy or in the
application). An open history API is not acceptable on any address a second
machine can reach. The finding history is in `backend/eval/DAY16_REPORT.md`
(H-1) and `backend/eval/DAY19_REPORT.md`.

## Tech stack

| Layer     | Technology                                  |
| --------- | ------------------------------------------- |
| Frontend  | React 19, TypeScript, Tailwind CSS 4, Vite   |
| Backend   | Python 3.12, FastAPI, Pydantic v2            |
| Database  | SQLite (standard-library `sqlite3`)          |
| Testing   | pytest (+ FastAPI TestClient), Vitest        |

## Project structure

```
phisguard/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py         # FastAPI app, routes, CORS, lifespan
│   │   ├── analyzer.py     # heuristics + risk scoring (pure, no network)
│   │   ├── providers/      # optional external threat intel (VirusTotal)
│   │   ├── database.py     # SQLite persistence (parameterized queries)
│   │   ├── schemas.py      # Pydantic request/response models
│   │   └── config.py       # env-based settings (no hardcoded secrets)
│   ├── tests/              # 11 test modules: analyzer, API, config, database,
│   │                       #   dataset import, deploy artifacts, eval, ops DB
│   │                       #   lifecycle, security, thresholds, VirusTotal
│   ├── ops/                # database backup/verify/restore tooling (Day 12)
│   ├── eval/               # evaluator + datasets + DAY6..DAY21 session reports
│   ├── requirements.txt
│   ├── .env.example
│   └── pytest.ini
├── deploy/                # systemd unit + nginx/Caddy reverse-proxy examples
├── scripts/
│   └── e2e-smoke.mjs      # end-to-end smoke test (real servers, temp DB)
├── frontend/
│   ├── src/
│   │   ├── api/client.ts       # typed API client
│   │   ├── api/client.test.ts  # Vitest: API client unit tests (Node env)
│   │   ├── *.test.tsx          # Vitest: render smoke + component tests (jsdom)
│   │   ├── components/         # RiskBadge, RiskGauge, FindingList, ...
│   │   ├── pages/              # Dashboard, ResultPage
│   │   ├── lib/risk.ts         # risk-label theme + colors
│   │   ├── App.tsx             # layout + routes
│   │   └── main.tsx
│   ├── .env.example
│   └── package.json
├── .gitignore
└── README.md
```

## Prerequisites

- Python 3.11+ (tested on 3.12)
- Node.js 20+ (tested on 24)

## 1. Run the backend

```powershell
cd backend

# One-time: create a virtual environment and install dependencies
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Start the API (http://127.0.0.1:8000).
# --host 127.0.0.1 is uvicorn's default; it is stated explicitly so the dev
# server is loopback-only and never answers requests from another machine.
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1
```

- Interactive API docs: <http://127.0.0.1:8000/docs> (disabled by default when
  `PHISHGUARD_ENVIRONMENT=production`; served only when enabled)
- Health check: <http://127.0.0.1:8000/api/health>
- The SQLite file `backend/phisguard.db` is created automatically on first run.

### Environment variables (optional)

Copy `backend/.env.example` to `backend/.env` to override defaults:

| Variable                       | Default                                             |
| ------------------------------ | --------------------------------------------------- |
| `PHISHGUARD_DATABASE_PATH`     | `phisguard.db`                                      |
| `PHISHGUARD_CORS_ORIGINS`      | `http://localhost:5173,http://127.0.0.1:5173`       |
| `PHISHGUARD_LOG_LEVEL`         | `info`                                              |
| `PHISHGUARD_ENVIRONMENT`       | `development`                                       |
| `PHISHGUARD_DOCS_ENABLED`      | *(auto: enabled in dev, disabled in prod)*          |
| `PHISHGUARD_HISTORY_LIMIT`     | `100` (1..1000; default matches API 1..100)         |
| `PHISHGUARD_MAX_REQUEST_BODY_BYTES` | `16384` (16 KiB)                                |
| `PHISHGUARD_RATE_LIMIT_ENABLED` | `false`                                          |
| `PHISHGUARD_RATE_LIMIT_REQUESTS` | `60`                                           |
| `PHISHGUARD_RATE_LIMIT_WINDOW_SECONDS` | `60`                                     |
| `VIRUSTOTAL_API_KEY`           | *(unset — external lookups disabled, offline mode)* |
| `PHISHGUARD_VIRUSTOTAL_ENABLED` | `true`                                             |
| `PHISHGUARD_VIRUSTOTAL_TIMEOUT_SECONDS` | `10`                                       |
| `PHISHGUARD_VIRUSTOTAL_BASE_URL` | `https://www.virustotal.com/api/v3`              |

> The VirusTotal key is read **only** from `VIRUSTOTAL_API_KEY` (no
> `PHISHGUARD_` prefix). It is never sent to the frontend and `.env` is
> git-ignored. Leave it unset to run entirely offline.

`backend/.env` is always read from the backend directory, regardless of the
working directory the server is started from. In production, invalid values fail
fast at startup (for example, a wildcard `PHISHGUARD_CORS_ORIGINS` is refused),
and a one-line, non-secret configuration summary is logged at startup.

## 2. Run the frontend

```powershell
cd frontend

# One-time install
npm install

# Start the dev server
npm run dev
```

The dev server listens on the IPv4 loopback address **`127.0.0.1:5173`** (see
`server.host` in `vite.config.ts`), so it answers on both
<http://localhost:5173> and <http://127.0.0.1:5173> and never from another
machine. IPv4 is chosen deliberately: on this platform `localhost` resolves to
the IPv6 loopback `::1`, and binding `localhost` would therefore listen on
`::1` only — leaving `http://127.0.0.1:5173` unreachable even though the
backend allow-lists that origin in `PHISHGUARD_CORS_ORIGINS`. Binding IPv4 also
matches uvicorn, which serves on `127.0.0.1:8000`. Either way this stays inside
the loopback-only scope described at the top of this README.

The frontend reads `VITE_API_BASE_URL` (default `http://localhost:8000`).

- **Development:** keep `http://localhost:8000` (or leave unset).
- **Production:** set `VITE_API_BASE_URL` to the public API origin, or leave it
  empty to use a relative path (`/api/...`) behind a reverse proxy that serves
  both the frontend build and the FastAPI API from the same origin. See
  `frontend/.env.example` for examples.

## 3. Run the tests

Backend:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
```

Frontend (Vitest), three suites. The API-client unit tests run in the default
Node environment; the render-smoke and component tests opt into a jsdom
environment per file (`// @vitest-environment jsdom`), so no global test
configuration is needed and no timers or real network calls are used —
`fetch` is stubbed in every component test:

```powershell
cd frontend
npm test            # vitest run (single pass)
npm run test:watch  # watch mode
```

Type-check / build the frontend:

```powershell
cd frontend
npm run build
```

Lint the frontend:

```powershell
cd frontend
npm run lint
```

### End-to-end smoke test

A separate, fourth check starts the **real** backend and the **real** built
frontend on isolated loopback ports (with a throwaway database), drives the full
flow over real HTTP — submit → result → history → unknown id → CORS → failure
and recovery — and always tears both servers down and deletes the temporary
data. It is deliberately **not** part of `npm test`, and it does not replace the
manual browser check. Build the frontend first, then run it:

```powershell
cd frontend
npm run build       # required: the smoke test serves frontend/dist
npm run test:e2e
```

or directly from the repository root: `node scripts/e2e-smoke.mjs`. It exits `0`
when every check passes and `1` on any failure, never touches
`backend/phisguard.db`, and makes no external network calls. See
`backend/eval/DAY20_REPORT.md` for what it covers and what it does not.

## API

| Method | Path                 | Description                                  |
| ------ | -------------------- | -------------------------------------------- |
| GET    | `/api/health`        | Service status, version, stored scan count   |
| POST   | `/api/analyze`       | Analyze `{ "url": "..." }`, store, return    |
| GET    | `/api/history`       | Recent scans (newest first), `?limit=1..100` (capped by `PHISHGUARD_HISTORY_LIMIT`) — **unauthenticated** |
| GET    | `/api/history/{id}`  | Full detail for a stored scan — **unauthenticated** |

Example:

```powershell
$body = @{ url = "http://paypal.com.secure-login.evil.net/verify" } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/analyze -Method Post `
  -Body $body -ContentType "application/json"
```

## How the risk score works

Each check produces an explainable *finding* with a fixed point weight. The
score is the sum of the weights, capped at 100.

Weights reflect the **strength of evidence**, not a verdict. Plain HTTP is a
transport weakness, not proof of phishing, so it scores only 15 points — a URL
whose only issue is HTTP stays in the **Low** band.

| Signal                                        | Points | Severity |
| --------------------------------------------- | ------ | -------- |
| Brand name hidden in a subdomain              | 30     | critical |
| Raw IP-address host                           | 25     | high     |
| Numeric/obfuscated IP host (e.g. `2130706433`, `0x7f000001`, `127.1`) | 25 | high |
| Punycode / IDN host                           | 25     | high     |
| Non-ASCII characters in host                  | 25     | high     |
| `@` in the authority section                  | 25     | high     |
| Brand name with extra words in the domain     | 25     | high     |
| Credentials embedded in the URL               | 25     | high     |
| Multiple credential/urgency keywords          | 25     | high     |
| Very long URL                                 | 25     | high     |
| Not HTTPS (weakness, not phishing on its own) | 15     | medium   |
| Double slash in path / heavy encoding / risky TLD / keyword / deep subdomains / hyphenated domain | 15 | medium |
| Non-standard port / long URL / long label / few subdomains | 10 | low |

Score → label: **Low** 0–24 · **Medium** 25–49 · **High** 50–74 · **Critical** 75–100.

Two checks are deliberately narrow to keep the score explainable:

- **Numeric hosts.** A host made up entirely of numbers that is *not* a canonical
  IPv4/IPv6 literal is flagged (`numeric_host`), because forms like `2130706433`,
  `0x7f000001` and `127.1` are alternate encodings of an IP address that some
  browsers still resolve.
- **Brand impersonation.** A brand matches only as a whole label token, or as a
  token *prefix* for brands longer than 3 characters. This keeps the short brand
  `ups` from matching unrelated words such as `groups`, and `chase` from matching
  `purchase`, while still catching `paypal-secure.com`, `paypallogin.com` and
  `appleid.evil.com`.

## Optional VirusTotal threat intelligence

External enrichment is **opt-in and additive**. Set `VIRUSTOTAL_API_KEY` to
enable it; without a key PhishGuard keeps working with the offline heuristics
only and the response reports `threat_intel.status = "disabled"`.

- **Lookup only, never submission.** PhishGuard computes the URL id
  (`base64url(sha256(url))`) and calls `GET /urls/{id}` to read an *existing*
  report. It never `POST`s a URL for scanning, so user URLs are not submitted to
  VirusTotal on the user's behalf.
- **Separate from scoring.** Threat intelligence is returned as its own
  `threat_intel` object. It **never** changes `risk_score` / `risk_label`, and
  the two systems are not merged, averaged, or re-labeled.
- **No false "safe" claims.** A clean report is reported as
  `verdict = "no_detections"`, which explicitly means *no vendor flagged it* —
  not that the URL is safe.

The provider's status is always reported, and the frontend shows the malicious
and suspicious detection counts and the last analysis date when a report exists:

| `status`        | Meaning                                                       |
| --------------- | ------------------------------------------------------------- |
| `disabled`      | No API key configured (offline mode).                         |
| `found`         | Report retrieved; counts + date are populated.                |
| `not_found`     | VirusTotal has no existing report for this URL.               |
| `rate_limited`  | HTTP 429 from VirusTotal.                                     |
| `timeout`       | Lookup exceeded `PHISHGUARD_VIRUSTOTAL_TIMEOUT_SECONDS`.      |
| `invalid_key`   | HTTP 401/403 — key invalid/expired/insufficient permissions.  |
| `error`         | Network failure, server error (5xx), or unexpected response.  |

The **verdict** is derived *only* from VirusTotal's `last_analysis_stats`:

| Condition                     | `verdict`        |
| ----------------------------- | ---------------- |
| `status != "found"`           | `unavailable`    |
| `malicious > 0`               | `malicious`      |
| else `suspicious > 0`         | `suspicious`     |
| else                          | `no_detections`  |

## Deployment and data lifecycle

Production templates live in [`deploy/`](deploy/README.md): a systemd unit
running a **single** uvicorn worker against a database on a persistent volume,
plus nginx/Caddy reverse-proxy examples for TLS termination, a request-body cap
and a shared rate limit. They are reviewed examples, **not validated
artifacts**: no proxy, service manager or TLS certificate was available where
they were written, so run `nginx -t` / `systemctl daemon-reload` (and obtain a
certificate) before relying on them. The local development commands above are
unaffected.

The SQLite database is the only stateful component, and it holds every URL users
have analyzed — **in cleartext**: SQLite applies no at-rest encryption here, so
the file is readable by anyone who can read `backend/phisguard.db` (or a backup
of it).

- Back up with SQLite's online backup API, not an OS copy of a live file:

  ```powershell
  cd backend
  .\.venv\Scripts\python.exe ops\db_lifecycle.py info
  .\.venv\Scripts\python.exe ops\db_lifecycle.py backup --label nightly
  .\.venv\Scripts\python.exe ops\db_lifecycle.py verify --backup backups\<file>.db
  ```

- Restore into a **separate** path first and validate it there; a restore over
  the live file keeps the previous one as `<name>.replaced-<timestamp>`.
- `retention-plan` only *reports* what a retention policy would remove. No
  retention policy and **no automatic deletion** are implemented.

See [`backend/ops/README.md`](backend/ops/README.md) for the full procedure,
retention options and limitations, and `backend/eval/DAY12_REPORT.md` for the
review behind them.

> ⚠️ **`GET /api/history` is unauthenticated** and returns every analyzed URL.
> Keep the service on a private network / VPN, or require authentication at the
> reverse proxy. The deployment examples do **not** make a publicly reachable,
> unauthenticated API safe. **For the local demo this is accepted** (Day 19),
> on the condition that the service stays bound to loopback; exposing it beyond
> loopback requires authentication first. Application authentication itself is a
> future product decision, not part of this demo.

## Security notes

- **No link fetching in the MVP.** `analyzer.py` works on the URL string only.
- **Input validation & normalization.** Only `http`/`https` are accepted;
  `javascript:`, `data:`, `file:`, empty, over-long (>2048 chars) and
  control-character inputs are rejected with HTTP 400/422.
- **SQL injection.** All database access uses parameterized queries.
- **XSS.** React escapes all rendered values by default; the UI never uses
  `dangerouslySetInnerHTML`, so URL content is displayed as text.
- **Secrets.** Configuration comes from environment variables; there are no
  hardcoded keys and `.env` files are git-ignored.

## Known limitations

These are intentional MVP scope limits and good next steps:

- Heuristics only for the risk score — no domain-age, WHOIS, or blocklist data.
- **Real-world detection accuracy has not been established.** The only
  evaluation in the repository is a 12-case *synthetic* fixture set
  (`backend/eval/fixtures.jsonl` / `EVALUATION_REPORT.md`). The accuracy,
  precision and recall figures there describe that tiny constructed set only —
  they are **not** a real-world detection rate, and no external
  PhishTank/Tranco-style dataset has been evaluated (`backend/eval/data/` does
  not exist). Do not quote those numbers as performance of the tool.
- VirusTotal integration is optional and only reads **existing** reports; URLs
  with no prior report are reported as `not_found` (PhishGuard does not submit
  them for scanning), so coverage depends on VirusTotal's existing data.
- External lookups run synchronously during `POST /api/analyze`, so a slow
  provider can add up to the configured timeout to that request.
- **No authentication on any endpoint**, including the history routes, which
  expose the URLs users have analyzed. For this local-only demo that is an
  **accepted, documented limitation** (Day 19 decision; see
  [Scope: local-only demo](#scope-local-only-demo)). It is contained *only* by
  the loopback bind, so the service must never listen on anything a second
  machine can reach. Accounts and ownership remain a future product decision,
  not an implemented feature; see `deploy/README.md`.
- The built-in in-memory rate limiter is **off by default** and is
  **process-scoped only** (not suitable for multi-worker or distributed
  deployments); the effective limit belongs at the reverse proxy
  (`deploy/nginx-phisguard.conf.example`).
- `GET /docs`, `/redoc` and `/openapi.json` are **disabled by default** in
  production (`PHISHGUARD_ENVIRONMENT=production`). The SQLite database file
  must live on a persistent volume in deployment; the path is resolved against
  `backend/` by default.
- **Scan history is unbounded.** No retention or rotation is implemented, and
  deletion is deliberately not automatic (`ops/db_lifecycle.py retention-plan`
  only reports what a policy *would* remove). Backups must be taken with the
  `ops/` tooling and stored encrypted.
- **SQLite is a single-writer store** with no WAL/busy-timeout tuning by the
  application, so run one process against the file. Recovery is limited to the
  last verified backup — there is no point-in-time recovery.
