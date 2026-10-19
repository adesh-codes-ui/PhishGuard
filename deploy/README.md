# Deployment artifacts

Minimal, single-worker deployment templates for PhishGuard, plus the reasoning
behind each choice. Everything here is a **template**: placeholders are marked
`<...>` and must be replaced.

> **Nothing in this directory was executed or validated on a real host.** The
> machine where these files were written had no `nginx`, `caddy`, `systemd`,
> `docker` or `openssl` binary, so no configuration was syntax-checked, no TLS
> certificate was issued, and no service was started from these files. The
> values that *can* be checked statically are pinned by tests in
> `backend/tests/test_deploy_artifacts.py` (body cap matches the app default,
> one uvicorn worker, persistent database path, no wildcard CORS, every
> environment key is a real setting). Treat this as a reviewed starting point,
> and run `nginx -t` / `caddy validate` / `systemctl daemon-reload` before use.

## Files

| File | Purpose |
| --- | --- |
| `phisguard.service` | systemd unit: one uvicorn worker on loopback, persistent state directory, restart policy. |
| `phishguard.env.example` | Production environment file for the unit (no secrets; offline by default). |
| `nginx-phisguard.conf.example` | nginx: TLS termination, HTTP→HTTPS redirect, body cap, **shared** rate limit, static frontend. |
| `Caddyfile.example` | Caddy alternative: automatic TLS + body cap. **No built-in rate limiter** (see the file header). |
| `README.md` | This document. |

Database backup/restore lives in `backend/ops/` — see `backend/ops/README.md`.

## Shape of the deployment

```
        Internet
           │  HTTPS (443)
           ▼
   ┌───────────────────┐        loopback only        ┌──────────────────────┐
   │ reverse proxy     │  ───────────────────────▶   │ uvicorn (1 worker)   │
   │ TLS, body cap,    │      http://127.0.0.1:8000  │ /opt/phisguard/...   │
   │ shared rate limit │                             └──────────┬───────────┘
   │ static frontend   │                                        │
   └───────────────────┘                                        ▼
                                                    /var/lib/phisguard/phisguard.db
                                                       (persistent volume)
```

One process, one worker, one SQLite file. This is deliberate, not a shortcut:

- the built-in rate limiter keeps its counters **in one process**, so
  `--workers N` multiplies the effective limit by N;
- SQLite is a **single-writer** store, so more writers mean more
  `database is locked` → HTTP 503.

If you need more concurrency, the next step is a shared rate limiter plus a
server database (Postgres/MySQL), not more workers.

## Prerequisites

- Linux host with systemd (235+ for `StateDirectory`, 240+ for `Type=exec`).
- Python 3.11+ (3.12 tested) with `python3 -m venv`.
- Node.js 20+ to build the frontend once.
- nginx **or** Caddy, and a DNS name pointing at the host.
- A TLS certificate: `certbot` (nginx) or Caddy's automatic TLS.

## Placeholders to replace

| Placeholder | Where | Notes |
| --- | --- | --- |
| `phisguard.example.com` | nginx, Caddyfile, env file | Real DNS name; the certificate must match it. |
| `/etc/letsencrypt/live/.../fullchain.pem`, `privkey.pem` | nginx | Only after `certbot` has issued them; nginx will not start if the paths do not exist. |
| `/opt/phisguard` | unit, README | Code checkout containing `backend/` and `.venv/`. |
| `/var/lib/phisguard` | unit (`StateDirectory`) | Created and owned by systemd. |
| `/etc/phisguard/phishguard.env` | unit | Root-owned, `chmod 640`, group = service group. |
| `/var/www/phisguard` | nginx, Caddyfile | Contents of `frontend/dist`. |

## Install (outline)

```bash
sudo useradd --system --home /opt/phisguard --shell /usr/sbin/nologin phisguard

# 1. Code + backend virtualenv
sudo git clone <your-fork-or-copy> /opt/phisguard         # or rsync the checkout
cd /opt/phisguard/backend
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt

# 2. Frontend build, served from the same origin as the API so the frontend can
#    use relative /api/... URLs (leave VITE_API_BASE_URL empty -- see
#    frontend/.env.example).
cd /opt/phisguard/frontend
npm ci && npm run build
sudo rsync -a --delete dist/ /var/www/phisguard/

# 3. Configuration (never commit the real file)
sudo install -d -m 750 /etc/phisguard
sudo install -o root -g phisguard -m 640 \
     /opt/phisguard/deploy/phishguard.env.example /etc/phisguard/phishguard.env
sudo nano /etc/phisguard/phishguard.env      # domain, database path, review

# 4. Service
sudo cp /opt/phisguard/deploy/phisguard.service /etc/systemd/system/phisguard.service
sudo chown -R phisguard:phisguard /opt/phisguard
sudo systemctl daemon-reload
sudo systemctl enable --now phisguard

# 5. Reverse proxy (TLS: get the certificate BEFORE validating the 443 block --
#    its ssl_certificate lines start commented out, so the TLS server is not
#    complete until certbot has issued the certificate and written or enabled it)
sudo cp /opt/phisguard/deploy/nginx-phisguard.conf.example /etc/nginx/conf.d/phisguard.conf
sudo certbot --nginx -d phisguard.example.com      # then review/uncomment ssl_certificate*
sudo nginx -t && sudo systemctl reload nginx       # re-run after ANY edit
# ...or, with Caddy: caddy validate --config ... && sudo systemctl reload caddy
```

## Environment configuration

`deploy/phishguard.env.example` is the template. The important settings:

| Setting | Production value | Why |
| --- | --- | --- |
| `PHISHGUARD_ENVIRONMENT` | `production` | Disables `/docs`, `/redoc`, `/openapi.json`, rejects a wildcard CORS origin at startup, logs deployment warnings. |
| `PHISHGUARD_DATABASE_PATH` | `/var/lib/phisguard/phisguard.db` | Absolute path on the persistent volume. |
| `PHISHGUARD_CORS_ORIGINS` | `https://phisguard.example.com` | Explicit origin only; `*` aborts startup in production. |
| `PHISHGUARD_MAX_REQUEST_BODY_BYTES` | `16384` | Must be ≤ the proxy body cap (`client_max_body_size 16k`). |
| `PHISHGUARD_RATE_LIMIT_ENABLED` | `false` | The real limit is the nginx example's shared `limit_req`; the app limiter is per process. The Caddy example has **no** limiter unless Caddy is built with `caddy-ratelimit`. |
| `VIRUSTOTAL_API_KEY` | unset | Keeps the deployment fully offline. Enabling it allows **lookup-only** enrichment (a URL is never submitted). |

Configuration is validated at startup and a one-line, non-secret summary is
logged, so `journalctl -u phisguard` confirms which values actually took effect.

## Health checks, startup, shutdown

- **Liveness/readiness:** `curl -fsS http://127.0.0.1:8000/api/health` → `{"status":"ok",...}`.
  Point monitors and load balancers at the loopback address; do **not** publish
  `/api/health` (it is unauthenticated and runs `COUNT(*)`).
- **Startup:** the service creates the database file and tables on first start
  (`CREATE TABLE IF NOT EXISTS` + additive migrations), then logs the
  configuration summary. First start also creates `/var/lib/phisguard`.
- **Failure to start** is intentional for unsafe configuration (e.g. a wildcard
  CORS origin in production): the process exits non-zero, `Restart=on-failure`
  will retry, and the reason is in the log.
- **Shutdown:** `systemctl stop phisguard` sends `SIGTERM`; uvicorn drains
  in-flight requests. `TimeoutStopSec=30` must stay above
  `PHISHGUARD_VIRUSTOTAL_TIMEOUT_SECONDS` (10s) if enrichment is enabled.
- **Restart after a restore:** SQLite has no "reload"; stop the service before
  restoring, then start it again and re-check `/api/health`. See
  `backend/ops/README.md`.
- **Upgrades:** back up first (`ops/db_lifecycle.py backup --label pre-upgrade`),
  redeploy, restart, verify `/api/health`. Schema changes are additive, so an
  older database keeps working.

## Backups

The database is the only stateful component; the frontend build and `.env` are
reproducible. Take backups with the tooling rather than an OS copy:

```bash
cd /opt/phisguard/backend
sudo -u phisguard ./.venv/bin/python ops/db_lifecycle.py backup --label nightly
sudo -u phisguard ./.venv/bin/python ops/db_lifecycle.py verify \
     --backup backups/phisguard-backup-<timestamp>.db
```

Then copy the `.db` and its `.db.json` manifest off-host (encrypted). Full
procedure, retention options and limitations: `backend/ops/README.md`.

## History access: the largest deployment risk

`GET /api/history` and `GET /api/history/{id}` are **unauthenticated**, and they
expose every URL analyzed on the instance — which may include private hostnames,
tokens in query strings, or anything a user pasted. `POST /api/analyze` is also
unauthenticated, so anyone who can reach it can consume CPU/quota.

The application has no user model, so there is nothing to authenticate against;
inventing one is a product decision (accounts, ownership, who may see whose
history), not a deployment tweak. The options, in order of least change:

| Option | Change | Cost / limitation |
| --- | --- | --- |
| **Keep it off the public internet** (private network, VPN, or bastion-only) | none | Recommended for the current build. Nothing to misconfigure, but it is not usable as a public service. |
| **Authenticate at the reverse proxy** (basic auth / mTLS / SSO in front of `/api/history*`) | proxy config only | Protects history, but the API itself is still anonymous: anyone who reaches the port directly bypasses it. Must be combined with the loopback bind (already in the unit) and a single ingress path. |
| **Add application authentication** | new scope: user model, tokens/sessions, ownership, and tests | The correct long-term answer, and explicitly out of scope here. |
| **Disable history entirely** | remove/guard the routes | Removes the feature; a product call. |

**This deployment example does not make a publicly reachable, unauthenticated
API safe, and does not pretend to.** The templates keep the app on loopback and
document proxy-side authentication.

The open-history question was **decided on Day 19 for the local demo only**: the
unauthenticated history API is accepted *because* the application is bound to
loopback, where the only possible client is the same user. That acceptance is
**conditional and does not carry over to a deployment** — the moment the API is
reachable from another machine, authenticating at the reverse proxy (or in the
application), or keeping it on a private network/VPN, becomes mandatory. The
finding history is in `backend/eval/DAY12_REPORT.md` (raised),
`backend/eval/DAY16_REPORT.md` (H-1) and `backend/eval/DAY19_REPORT.md`
(decision).

## Trusted-proxy assumptions

These are explicit, and are the *only* reason forwarded headers are honoured:

- uvicorn binds `127.0.0.1` only, so the only possible peer is the local proxy.
- The unit passes `--proxy-headers --forwarded-allow-ips=127.0.0.1`
  (trusted-proxy configuration). Remove both flags if no proxy overwrites
  `X-Forwarded-*`.
- The proxy **overwrites** `X-Forwarded-For` (`$proxy_add_x_forwarded_for` in
  nginx, `header_up` in Caddy) rather than forwarding client-supplied values
  blindly.
- PhishGuard itself never uses `X-Forwarded-For`: the in-process limiter keys on
  the transport peer address. Rate limiting is the proxy's job.
- Do not add a second, untrusted ingress path (e.g. a container port published
  directly to the internet) to the same process.

## Local development is unchanged

None of this affects day-to-day development:

```powershell
cd backend ; .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
cd frontend ; npm run dev
```

The defaults in `backend/.env.example` stay development-safe (docs enabled,
localhost CORS, rate limiting off, relative database path). The deployment
templates are opt-in files that nothing reads unless you install them.

## Not provided (and why)

- **No Docker/Compose file.** Adding one without being able to build or run it
  here would be an unverified artifact; the unit + proxy pair is the smallest
  thing that can be reviewed end to end.
- **No multi-worker / multi-replica setup.** Blocked by the per-process limiter
  and SQLite's single writer (see above).
- **No secret manager integration.** `VIRUSTOTAL_API_KEY` is optional; the
  environment-file pattern is documented instead.
- **No CI/CD, log shipping, or metrics.** Out of scope; only web access logs
  are produced today.
- **No TLS in the application.** Termination belongs at the proxy.
