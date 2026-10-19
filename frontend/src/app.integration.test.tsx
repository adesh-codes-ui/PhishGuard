// @vitest-environment jsdom
/**
 * Component / integration tests for the dashboard and result pages.
 *
 * These run in a jsdom environment (chosen per file, so the API-client unit
 * tests keep running in the faster default Node environment) and use
 * @testing-library/react plus @testing-library/user-event.
 *
 * Rules followed here, deliberately:
 * - every request is served from an in-memory stub; neither a real backend nor
 *   the network is touched, and no request is left to "not matter";
 * - no timers, no sleeps, no polling: loading states are driven by promises the
 *   test resolves itself, and settled states are awaited with `findBy*`;
 * - an unmocked URL returns a loud 599 instead of looking like an outage, so a
 *   test cannot pass for the wrong reason;
 * - `cleanup` runs after every test because Vitest is configured with
 *   `globals: false`, so Testing Library's automatic cleanup is not registered.
 *
 * Note: the app is rendered without React.StrictMode here. StrictMode's
 * development-only double invocation of effects is verified manually in a
 * browser, not in this suite.
 */

import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, useNavigate } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import type {
  Analysis,
  ScanDetail,
  ScanSummary,
  ThreatIntel,
} from './api/client'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SCAN_A_URL = 'http://paypal.com.secure-login.evil.net/verify'
const SCAN_A_HOST = 'paypal.com.secure-login.evil.net'

const SCAN_B_URL = 'https://login-security-update.example.net/account'
const SCAN_B_HOST = 'login-security-update.example.net'

const NOT_FOUND_DETAIL = 'Scan not found.'
const UNREACHABLE_MESSAGE =
  'Could not reach the PhishGuard API. Is the backend running?'

const summaryA: ScanSummary = {
  id: 1,
  url: SCAN_A_URL,
  normalized_url: SCAN_A_URL,
  host: SCAN_A_HOST,
  risk_score: 80,
  risk_label: 'Critical',
  created_at: '2026-10-19T12:00:00Z',
}

const summaryB: ScanSummary = {
  id: 2,
  url: SCAN_B_URL,
  normalized_url: SCAN_B_URL,
  host: SCAN_B_HOST,
  risk_score: 45,
  risk_label: 'Medium',
  created_at: '2026-10-19T12:30:00Z',
}

const disabledIntel: ThreatIntel = {
  provider: 'virustotal',
  status: 'disabled',
  available: false,
  verdict: 'unavailable',
  message: 'Threat intelligence is disabled: no API key is configured.',
  malicious: null,
  suspicious: null,
  harmless: null,
  undetected: null,
  total_engines: null,
  last_analysis_date: null,
  permalink: null,
}

/** POST /api/analyze response. */
const analysisA: Analysis = {
  id: 1,
  input_url: SCAN_A_URL,
  normalized_url: SCAN_A_URL,
  scheme: 'http',
  host: SCAN_A_HOST,
  registrable_domain: 'evil.net',
  risk_score: 80,
  risk_label: 'Critical',
  findings: [
    {
      code: 'brand_in_subdomain',
      title: 'Brand name in subdomain',
      description: 'The host mentions a brand outside its registrable domain.',
      points: 30,
      severity: 'high',
    },
    {
      code: 'no_https',
      title: 'No HTTPS',
      description: 'The URL uses plain HTTP.',
      points: 50,
      severity: 'medium',
    },
  ],
  disclaimer: 'Static heuristic analysis. Not proof that a URL is safe.',
  created_at: '2026-10-19T12:00:00Z',
  threat_intel: disabledIntel,
}

/** GET /api/history/{id} response. */
const detailA: ScanDetail = {
  ...summaryA,
  scheme: 'http',
  registrable_domain: 'evil.net',
  findings: analysisA.findings,
  // Exercises the "no external result recorded" branch of ThreatIntelPanel.
  threat_intel: null,
}

const detailB: ScanDetail = {
  ...summaryB,
  scheme: 'https',
  registrable_domain: 'example.net',
  findings: analysisA.findings,
  threat_intel: disabledIntel,
}

// ---------------------------------------------------------------------------
// Request stubbing helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 404 ? 'Not Found' : 'OK',
    json: async () => body,
  } as unknown as Response
}

const fetchMock = vi.fn<(input: string, init?: RequestInit) => Promise<Response>>()

/** A URL the test did not plan for: fail loudly rather than look like an outage. */
function unmocked(url: string): Response {
  return jsonResponse({ detail: `UNMOCKED REQUEST IN TEST: ${url}` }, 599)
}

function mockApi(handler: (url: string) => Response) {
  fetchMock.mockImplementation(async (input) => handler(String(input)))
}

/** Dashboard with no stored scans and a successful analyze response. */
function dashboardHandler(url: string): Response {
  if (url.includes('/api/analyze')) return jsonResponse(analysisA)
  if (url.includes('/api/history')) return jsonResponse({ total: 0, items: [] })
  return unmocked(url)
}

/** A promise the test resolves by hand, to hold a request in flight. */
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )
}

/**
 * Renders the app with an extra button that navigates to `to` through the same
 * router, so a route change can be triggered without unmounting the app. This
 * is how the result page's keyed remount is exercised.
 */
function renderAppWithGo(path: string, to: string) {
  function GoTo() {
    const navigate = useNavigate()
    return (
      <button type="button" onClick={() => navigate(to)}>
        {`go:${to}`}
      </button>
    )
  }

  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
      <GoTo />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

describe('dashboard', () => {
  it('shows the history loading state first, then the empty state', async () => {
    const pending = deferred<Response>()
    fetchMock.mockReturnValueOnce(pending.promise)

    renderApp('/')

    expect(screen.getByRole('status')).toBeTruthy()
    expect(screen.getByText('Loading history…')).toBeTruthy()

    await act(async () => {
      pending.resolve(jsonResponse({ total: 0, items: [] }))
    })

    expect(
      screen.getByText('No scans yet. Analyze a URL to build your history.'),
    ).toBeTruthy()
    expect(screen.queryByText('Loading history…')).toBeNull()
    expect(String(fetchMock.mock.calls[0][0])).toContain('/api/history?limit=15')
  })

  it('lists stored scans with their risk badge and links to the result page', async () => {
    mockApi((url) => {
      if (url.includes('/api/history')) {
        return jsonResponse({ total: 2, items: [summaryA, summaryB] })
      }
      return unmocked(url)
    })

    renderApp('/')

    expect(await screen.findByText(SCAN_A_HOST)).toBeTruthy()
    expect(screen.getByText(SCAN_B_HOST)).toBeTruthy()
    expect(screen.getByText('Critical')).toBeTruthy()
    expect(screen.getByText('80/100')).toBeTruthy()
    expect(screen.getByText('Medium')).toBeTruthy()
    expect(screen.getByText('45/100')).toBeTruthy()

    const link = screen.getByRole('link', { name: new RegExp(SCAN_A_HOST) })
    expect(link.getAttribute('href')).toBe('/result/1')
  })

  it('announces a history failure in an alert and recovers on Refresh', async () => {
    let attempt = 0
    fetchMock.mockImplementation(async (input) => {
      attempt += 1
      if (attempt === 1) throw new TypeError('Failed to fetch')
      if (String(input).includes('/api/history')) {
        return jsonResponse({ total: 1, items: [summaryA] })
      }
      return unmocked(String(input))
    })

    renderApp('/')

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toBe(UNREACHABLE_MESSAGE)

    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }))

    expect(await screen.findByText(SCAN_A_HOST)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(attempt).toBe(2)
  })

  it('submits the trimmed URL and renders the returned risk level and score', async () => {
    mockApi((url) => {
      if (url.includes('/api/analyze')) return jsonResponse(analysisA)
      if (url.endsWith('/api/history/1')) return jsonResponse(detailA)
      if (url.includes('/api/history')) return jsonResponse({ total: 0, items: [] })
      return unmocked(url)
    })

    const { container } = renderApp('/')

    await userEvent.type(
      screen.getByLabelText('URL to analyze'),
      `   ${SCAN_A_URL}   `,
    )
    await userEvent.click(screen.getByRole('button', { name: 'Analyze URL' }))

    // Landed on the result page and rendered the score it was given. The name
    // matters: the dashboard also has an h1, so an unnamed query would match
    // before the navigation has happened.
    expect(
      await screen.findByRole('heading', { level: 1, name: SCAN_A_HOST }),
    ).toBeTruthy()
    expect(screen.getByText('Critical')).toBeTruthy()
    expect(screen.getByText('80/100')).toBeTruthy()
    expect(
      screen.getByRole('heading', { level: 2, name: 'Why this score (2 findings)' }),
    ).toBeTruthy()
    expect(screen.getByText('Brand name in subdomain')).toBeTruthy()
    expect(screen.getByText('+30')).toBeTruthy()

    // The decorative gauge must not be the only carrier of the score.
    const svgs = Array.from(container.querySelectorAll('svg'))
    expect(svgs.length).toBeGreaterThan(0)
    expect(svgs.every((svg) => svg.getAttribute('aria-hidden') === 'true')).toBe(
      true,
    )

    // The exact request that was sent, including the whitespace trim.
    const analyzeCall = fetchMock.mock.calls.find(([url]) =>
      String(url).includes('/api/analyze'),
    )
    expect(analyzeCall).toBeDefined()
    expect(analyzeCall?.[1]?.method).toBe('POST')
    expect(analyzeCall?.[1]?.body).toBe(JSON.stringify({ url: SCAN_A_URL }))
    expect(
      (analyzeCall?.[1]?.headers as Record<string, string> | undefined)?.[
        'Content-Type'
      ],
    ).toBe('application/json')
  })

  it('keeps the submit button disabled for empty and whitespace-only input', async () => {
    mockApi(dashboardHandler)

    renderApp('/')

    expect(
      screen.getByRole('button', { name: 'Analyze URL' }).hasAttribute('disabled'),
    ).toBe(true)

    await userEvent.type(screen.getByLabelText('URL to analyze'), '    ')

    expect(
      screen.getByRole('button', { name: 'Analyze URL' }).hasAttribute('disabled'),
    ).toBe(true)
    expect(
      fetchMock.mock.calls.filter(([url]) => String(url).includes('/api/analyze')),
    ).toHaveLength(0)
  })
})

// ---------------------------------------------------------------------------
// Result page
// ---------------------------------------------------------------------------

describe('result page', () => {
  it('renders the score, label, findings and the no-intel branch for a scan', async () => {
    mockApi((url) => {
      if (url.endsWith('/api/history/1')) return jsonResponse(detailA)
      return unmocked(url)
    })

    renderApp('/result/1')

    expect(
      await screen.findByRole('heading', { level: 1, name: SCAN_A_HOST }),
    ).toBeTruthy()
    expect(screen.getByText('Critical')).toBeTruthy()
    expect(screen.getByText('80/100')).toBeTruthy()
    expect(
      screen.getByRole('heading', { level: 2, name: 'Why this score (2 findings)' }),
    ).toBeTruthy()
    expect(
      screen.getByText(
        'No external threat-intelligence result was recorded for this scan.',
      ),
    ).toBeTruthy()
    expect(
      screen.getByText(/not proof that a URL is safe or unsafe/),
    ).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(String(fetchMock.mock.calls[0][0])).toContain('/api/history/1')
  })

  it('shows the not-found state for a missing id, without an error alert', async () => {
    mockApi((url) => {
      if (url.includes('/api/history/999999')) {
        return jsonResponse({ detail: NOT_FOUND_DETAIL }, 404)
      }
      return unmocked(url)
    })

    renderApp('/result/999999')

    expect(await screen.findByText('Scan not found')).toBeTruthy()
    expect(
      screen.getByText('This scan id does not exist in the history.'),
    ).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByRole('link', { name: 'Back to dashboard' })).toBeTruthy()
  })

  it('announces a non-404 failure and recovers when Retry is used', async () => {
    let attempt = 0
    fetchMock.mockImplementation(async (input) => {
      attempt += 1
      if (attempt === 1) {
        return jsonResponse({ detail: 'Database is unavailable.' }, 500)
      }
      if (String(input).endsWith('/api/history/1')) return jsonResponse(detailA)
      return unmocked(String(input))
    })

    renderApp('/result/1')

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('Database is unavailable.')
    expect(screen.queryByText('Scan not found')).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))

    expect(
      await screen.findByRole('heading', { level: 1, name: SCAN_A_HOST }),
    ).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(attempt).toBe(2)
  })

  it('replaces a not-found page with the scan when only the id changes', async () => {
    mockApi((url) => {
      if (url.endsWith('/api/history/999999')) {
        return jsonResponse({ detail: NOT_FOUND_DETAIL }, 404)
      }
      if (url.endsWith('/api/history/1')) return jsonResponse(detailA)
      return unmocked(url)
    })

    renderAppWithGo('/result/999999', '/result/1')

    expect(await screen.findByText('Scan not found')).toBeTruthy()

    await userEvent.click(screen.getByRole('button', { name: 'go:/result/1' }))

    // Without the keyed remount the stale not-found flag would keep this hidden.
    expect(
      await screen.findByRole('heading', { level: 1, name: SCAN_A_HOST }),
    ).toBeTruthy()
    expect(screen.queryByText('Scan not found')).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('does not carry a loaded scan over to a different id', async () => {
    mockApi((url) => {
      if (url.endsWith('/api/history/1')) return jsonResponse(detailA)
      if (url.endsWith('/api/history/2')) return jsonResponse(detailB)
      return unmocked(url)
    })

    renderAppWithGo('/result/1', '/result/2')

    expect(
      await screen.findByRole('heading', { level: 1, name: SCAN_A_HOST }),
    ).toBeTruthy()
    expect(screen.getByText('Critical')).toBeTruthy()

    await userEvent.click(screen.getByRole('button', { name: 'go:/result/2' }))

    expect(
      await screen.findByRole('heading', { level: 1, name: SCAN_B_HOST }),
    ).toBeTruthy()
    expect(screen.getByText('Medium')).toBeTruthy()
    expect(screen.getByText('45/100')).toBeTruthy()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(SCAN_B_HOST)
    expect(screen.queryByText('Critical')).toBeNull()
  })
})
