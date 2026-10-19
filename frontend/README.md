# PhishGuard — frontend

React 19 + TypeScript + Vite single-page app for the PhishGuard **local-only
demo**. It renders the URL submission form, the explainable result page, and the
scan history, and talks to the FastAPI backend at `http://localhost:8000` (see
`VITE_API_BASE_URL` below).

The authoritative project documentation is the repository root
[`README.md`](../README.md). This file only covers the frontend.

## Scope

Local-only, single-user, bound to the IPv4 loopback `127.0.0.1` (set in
`vite.config.ts`). It is **not** configured for public deployment, and the app
has no authentication. See the root README and `deploy/README.md` before
exposing anything.

## Scripts

| Command | What it does |
| --- | --- |
| `npm run dev` | Vite dev server on `http://127.0.0.1:5173` (HMR). |
| `npm run build` | Type-check (`tsc -b`) then produce `dist/`. |
| `npm run preview` | Serve the built `dist/` locally. |
| `npm test` | Vitest single pass (3 files: API-client unit tests in Node, render-smoke + component tests in jsdom). |
| `npm run test:watch` | Vitest in watch mode. |
| `npm run lint` | Oxlint. |
| `npm run test:e2e` | End-to-end smoke test: starts the real backend and the built frontend, drives the flow, then cleans up. Requires `npm run build` first. |

## API base URL

The client reads `VITE_API_BASE_URL` (default `http://localhost:8000`) and
prefixes every request with `/api/`. To override, copy `.env.example` to `.env`.
Leaving it empty makes the app use relative `/api/...` paths (useful behind a
reverse proxy that serves the build and the API from one origin).

## Testing notes

- The API-client unit tests run in Vitest's default **Node** environment.
- The render-smoke and component tests opt into **jsdom** per file
  (`// @vitest-environment jsdom`), so no global test config is needed.
- Every component test **stubs `fetch`** — no real backend or network is used,
  and no timers or sleeps are involved.
- The end-to-end smoke test (`npm run test:e2e`) is the only check that starts
  real processes; it uses isolated temporary data and does not touch
  `backend/phisguard.db`.
