#!/usr/bin/env node
/**
 * PhishGuard end-to-end smoke test (Day 20).
 *
 * Starts the REAL backend (uvicorn) and the REAL built frontend (vite preview)
 * on isolated loopback ports, waits for both to become ready by polling, drives
 * the full flow over real HTTP, and always tears everything down.
 *
 * Dependencies: none. Node built-ins + the global `fetch` only.
 *
 * Guarantees / safety:
 * - Both servers bind `127.0.0.1` only. The script also checks `netstat` that
 *   no `0.0.0.0`/`[::]` listener appeared for its ports (Windows only).
 * - All state lives in a fresh temporary directory; `backend/phisguard.db` is
 *   NEVER touched (the child's PHISHGUARD_DATABASE_PATH always points at a temp
 *   file). The temp directory is removed on success, failure or signal.
 * - `VIRUSTOTAL_API_KEY` and any ambient `PHISHGUARD_*` variables are stripped
 *   from the child environment, so no external service is ever contacted.
 * - No arbitrary sleeps are used for synchronisation: readiness and the
 *   post-stop "is it down yet" check are bounded polls. The only timers are a
 *   per-request timeout and the poll interval.
 *
 * Usage (from the repository root, after `npm run build` in frontend/):
 *     node scripts/e2e-smoke.mjs
 * or from frontend/:
 *     npm run test:e2e
 *
 * Exit code: 0 when every check passes, 1 on any failure (or startup error).
 */

import { execFileSync, spawn } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url))
const REPO_ROOT = path.resolve(SCRIPT_DIR, '..')
const BACKEND_DIR = path.join(REPO_ROOT, 'backend')
const FRONTEND_DIR = path.join(REPO_ROOT, 'frontend')

// Deterministic, offline test data. This URL is the same one the backend and
// frontend suites use and scores "Critical" from the heuristics alone.
const PHISHING_URL = 'http://paypal.com.secure-login.evil.net/verify-account'
const PHISHING_HOST = 'paypal.com.secure-login.evil.net'
const ALLOWED_ORIGIN = 'http://localhost:5173'
const DENIED_ORIGIN = 'https://evil.example'

const REQUEST_TIMEOUT_MS = 5000
const READY_TIMEOUT_MS = 40000
const POLL_INTERVAL_MS = 150

const results = []
let backend = null
let frontend = null
let tempDir = null

// --- tiny test harness ----------------------------------------------------- #

function pass(name) {
  results.push({ name, status: 'pass' })
  console.log(`  PASS  ${name}`)
}
function skip(name, why) {
  results.push({ name, status: 'skip', why })
  console.log(`  SKIP  ${name} (${why})`)
}
function check(name, condition, detail) {
  if (condition) {
    pass(name)
    return
  }
  results.push({ name, status: 'fail', detail })
  console.log(`  FAIL  ${name}`)
  if (detail) console.log(`        ${detail}`)
  throw new Error(`E2E check failed: ${name}`)
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** fetch with an abort timeout so a hung socket cannot stall the run. */
async function http(url, init = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    return await fetch(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

/** Poll `predicate(url)` until it is satisfied or the deadline passes. */
async function waitForReady(label, url, predicate, timeoutMs = READY_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs
  let last = 'no attempt'
  while (Date.now() < deadline) {
    try {
      const response = await http(url)
      if (await predicate(response)) return
      last = `status ${response.status}`
    } catch (error) {
      last = error?.message ?? String(error)
    }
    await delay(POLL_INTERVAL_MS)
  }
  throw new Error(`Timed out waiting for ${label} at ${url} (last: ${last})`)
}

// --- process helpers ------------------------------------------------------- #

/** A free port on the IPv4 loopback interface. */
function freeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.unref()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

/** Locate the backend virtualenv interpreter (overridable for CI/other OSes). */
function backendPython() {
  if (process.env.PHISHGUARD_E2E_PYTHON) return process.env.PHISHGUARD_E2E_PYTHON
  const venv =
    process.platform === 'win32'
      ? path.join(BACKEND_DIR, '.venv', 'Scripts', 'python.exe')
      : path.join(BACKEND_DIR, '.venv', 'bin', 'python')
  if (existsSync(venv)) return venv
  return process.platform === 'win32' ? 'python' : 'python3'
}

/** A child environment with ambient PhishGuard/VirusTotal config removed. */
function childEnv(extra = {}) {
  const env = { ...process.env }
  for (const key of Object.keys(env)) {
    if (key.startsWith('PHISHGUARD_') || key === 'VIRUSTOTAL_API_KEY') delete env[key]
  }
  return { ...env, PYTHONUNBUFFERED: '1', ...extra }
}

function capture(child, sink) {
  child.stdout?.on('data', (chunk) => {
    sink.value += chunk
  })
  child.stderr?.on('data', (chunk) => {
    sink.value += chunk
  })
}

function startBackend(port, databasePath) {
  const sink = { value: '' }
  const child = spawn(
    backendPython(),
    ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(port), '--log-level', 'warning'],
    {
      cwd: BACKEND_DIR,
      env: childEnv({ PHISHGUARD_DATABASE_PATH: databasePath }),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    },
  )
  capture(child, sink)
  child.on('error', (error) => {
    sink.value += `\n[backend spawn error] ${error?.message ?? error}\n`
  })
  child.on('exit', (code, signal) => {
    sink.value += `\n[backend exited code=${code} signal=${signal}]\n`
  })
  backendLogSink = sink
  return child
}

// Keep a handle on the current backend log sink so a restart keeps appending.
let backendLogSink = null

function startFrontend(port) {
  const sink = { value: '' }
  const viteBin = path.join(FRONTEND_DIR, 'node_modules', 'vite', 'bin', 'vite.js')
  if (!existsSync(viteBin)) {
    throw new Error(`vite not found at ${viteBin} — run 'npm install' in frontend/ first.`)
  }
  const child = spawn(
    process.execPath,
    [viteBin, 'preview', '--host', '127.0.0.1', '--port', String(port), '--strictPort'],
    {
      cwd: FRONTEND_DIR,
      env: childEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    },
  )
  capture(child, sink)
  child.on('error', (error) => {
    sink.value += `\n[frontend spawn error] ${error?.message ?? error}\n`
  })
  child.on('exit', (code, signal) => {
    sink.value += `\n[frontend exited code=${code} signal=${signal}]\n`
  })
  frontendLogSink = sink
  return child
}

let frontendLogSink = null

function waitForExit(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve(true)
    const timer = setTimeout(() => resolve(false), timeoutMs)
    child.once('exit', () => {
      clearTimeout(timer)
      resolve(true)
    })
  })
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  // A child that never spawned (e.g. bad interpreter) has no pid to signal.
  if (child.pid === undefined) return
  try {
    child.kill('SIGTERM')
  } catch {
    /* already gone */
  }
  if (await waitForExit(child, 4000)) return
  if (process.platform === 'win32') {
    try {
      execFileSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore' })
    } catch {
      /* best effort */
    }
  } else {
    try {
      child.kill('SIGKILL')
    } catch {
      /* best effort */
    }
  }
  await waitForExit(child, 4000)
}

async function cleanup() {
  await stopChild(backend)
  await stopChild(frontend)
  backend = null
  frontend = null
  if (tempDir && existsSync(tempDir)) {
    try {
      rmSync(tempDir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
  }
}

// --- checks ---------------------------------------------------------------- #

/**
 * Best-effort proof that our servers did not bind a wildcard address.
 * Windows-only; on other platforms this is reported as skipped, never "passed".
 */
function checkLoopbackOnly(ports) {
  if (process.platform !== 'win32') {
    skip('servers bind loopback only (no 0.0.0.0)', 'netstat check is Windows-only')
    return
  }
  let output
  try {
    output = execFileSync('netstat', ['-ano'], { encoding: 'utf8' })
  } catch {
    skip('servers bind loopback only (no 0.0.0.0)', 'netstat unavailable')
    return
  }
  const wanted = new Set(ports.map(String))
  const wildcard = []
  for (const rawLine of output.split(/\r?\n/)) {
    const match = rawLine.trim().match(/^TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING\s+(\d+)$/)
    if (!match) continue
    const [, address, port] = match
    if (!wanted.has(port)) continue
    if (address === '0.0.0.0' || address === '[::]' || address === '::') wildcard.push(rawLine.trim())
  }
  check(
    'servers bind loopback only (no 0.0.0.0 / [::])',
    wildcard.length === 0,
    wildcard.join(' | '),
  )
}

// --- main ------------------------------------------------------------------ #

async function main() {
  if (!existsSync(path.join(FRONTEND_DIR, 'dist', 'index.html'))) {
    throw new Error(
      "frontend/dist/index.html is missing — run 'npm run build' in frontend/ before the E2E run.",
    )
  }

  tempDir = mkdtempSync(path.join(os.tmpdir(), 'phisguard-e2e-'))
  const databasePath = path.join(tempDir, 'e2e.db')
  const backendPort = await freeLoopbackPort()
  const frontendPort = await freeLoopbackPort()
  const api = `http://127.0.0.1:${backendPort}`
  const ui = `http://127.0.0.1:${frontendPort}`

  console.log('PhishGuard E2E smoke test')
  console.log(`  backend  : ${api}  (isolated db: ${databasePath})`)
  console.log(`  frontend : ${ui}  (serving frontend/dist)`)
  console.log(`  repository db 'backend/phisguard.db' is not used.\n`)

  backend = startBackend(backendPort, databasePath)
  frontend = startFrontend(frontendPort)

  // Readiness (bounded polling, no fixed sleeps).
  await waitForReady(
    'backend /api/health',
    `${api}/api/health`,
    async (response) => response.status === 200 && (await response.clone().json()).status === 'ok',
  )
  pass('backend process starts and answers on loopback (/api/health 200)')

  await waitForReady(
    'frontend index',
    `${ui}/`,
    async (response) => response.status === 200 && (await response.clone().text()).includes('id="root"'),
  )
  pass('frontend preview serves the built SPA shell')

  checkLoopbackOnly([backendPort, frontendPort])

  // --- empty isolated database -------------------------------------------- #
  let response = await http(`${api}/api/health`)
  let body = await response.json()
  check('a fresh isolated database starts empty', body.scans_stored === 0, `scans_stored=${body.scans_stored}`)

  // --- submit a URL ------------------------------------------------------- #
  response = await http(`${api}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: PHISHING_URL }),
  })
  body = await response.json()
  check('POST /api/analyze returns 200', response.status === 200, `status=${response.status}`)
  check(
    'real analyzer scores the phishing URL Critical (>=50)',
    body.risk_label === 'Critical' && body.risk_score >= 50,
    `label=${body.risk_label} score=${body.risk_score}`,
  )
  check(
    'external threat intel is offline (status=disabled)',
    body.threat_intel?.status === 'disabled',
    `status=${body.threat_intel?.status}`,
  )
  const scanId = body.id

  check(
    'the isolated SQLite file was created on disk',
    existsSync(databasePath) && statSync(databasePath).size > 0,
    `path=${databasePath}`,
  )

  // --- the result data the result page renders ---------------------------- #
  response = await http(`${api}/api/history/${scanId}`)
  body = await response.json()
  check(
    'GET /api/history/{id} returns the full result payload',
    response.status === 200 &&
      body.id === scanId &&
      body.host === PHISHING_HOST &&
      Array.isArray(body.findings) &&
      body.findings.length >= 1,
    `status=${response.status} findings=${body.findings?.length}`,
  )

  // --- history (the dashboard list) --------------------------------------- #
  response = await http(`${api}/api/history?limit=15`)
  body = await response.json()
  check(
    'GET /api/history lists the stored scan',
    body.total === 1 && body.items?.length === 1 && body.items[0].host === PHISHING_HOST,
    `total=${body.total} items=${body.items?.length}`,
  )

  // --- unknown scan id ---------------------------------------------------- #
  response = await http(`${api}/api/history/999999`)
  check('an unknown scan id returns 404', response.status === 404, `status=${response.status}`)

  // --- CORS over a real socket -------------------------------------------- #
  const allowedPreflight = await http(`${api}/api/analyze`, {
    method: 'OPTIONS',
    headers: { Origin: ALLOWED_ORIGIN, 'Access-Control-Request-Method': 'POST' },
  })
  check(
    'CORS preflight allows the configured origin',
    allowedPreflight.status === 200 &&
      allowedPreflight.headers.get('access-control-allow-origin') === ALLOWED_ORIGIN,
    `status=${allowedPreflight.status} acao=${allowedPreflight.headers.get('access-control-allow-origin')}`,
  )
  const deniedPreflight = await http(`${api}/api/analyze`, {
    method: 'OPTIONS',
    headers: { Origin: DENIED_ORIGIN, 'Access-Control-Request-Method': 'POST' },
  })
  check(
    'CORS preflight does not allow an unknown origin',
    !deniedPreflight.headers.get('access-control-allow-origin'),
    `acao=${deniedPreflight.headers.get('access-control-allow-origin')}`,
  )

  // --- SPA routes are served (what the browser loads) --------------------- #
  for (const route of ['/', `/result/${scanId}`, '/result/999999']) {
    const res = await http(`${ui}${route}`)
    const text = await res.text()
    check(
      `frontend serves the SPA shell for ${route}`,
      res.status === 200 && text.includes('id="root"'),
      `status=${res.status}`,
    )
  }

  // --- API failure and recovery ------------------------------------------- #
  console.log('\n  (failure and recovery)')
  await stopChild(backend)
  backend = null

  let refused = false
  const refuseDeadline = Date.now() + 10000
  while (Date.now() < refuseDeadline) {
    try {
      await http(`${api}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: PHISHING_URL }),
      })
    } catch {
      refused = true
      break
    }
    await delay(POLL_INTERVAL_MS)
  }
  check('requests fail once the backend is stopped', refused, 'backend still answered after stop')

  backend = startBackend(backendPort, databasePath)
  await waitForReady('backend restart', `${api}/api/health`, async (response) => response.status === 200)
  response = await http(`${api}/api/history`)
  body = await response.json()
  check(
    'history survives a backend restart (SQLite persistence across processes)',
    body.total === 1,
    `total=${body.total}`,
  )
}

// --- entry point ----------------------------------------------------------- #

let exitCode = 0
let shuttingDown = false
async function onSignal(signal) {
  if (shuttingDown) return
  shuttingDown = true
  console.log(`\nReceived ${signal}; cleaning up …`)
  await cleanup()
  process.exit(signal === 'SIGINT' ? 130 : 143)
}
process.on('SIGINT', () => void onSignal('SIGINT'))
process.on('SIGTERM', () => void onSignal('SIGTERM'))

try {
  await main()
  console.log('\nALL CHECKS PASSED')
} catch (error) {
  exitCode = 1
  const message = error?.message ?? String(error)
  if (!results.some((r) => r.status === 'fail')) {
    results.push({ name: 'unexpected error', status: 'fail', detail: message })
  }
  console.log(`\nE2E FAILED: ${message}`)
  const backendText = backendLogSink?.value?.trim()
  const frontendText = frontendLogSink?.value?.trim()
  if (backendText) console.log(`\n--- backend log ---\n${backendText}`)
  if (frontendText) console.log(`\n--- frontend log ---\n${frontendText}`)
} finally {
  await cleanup()
}

const passed = results.filter((r) => r.status === 'pass').length
const failed = results.filter((r) => r.status === 'fail').length
const skipped = results.filter((r) => r.status === 'skip').length
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`)
process.exit(exitCode)
