/**
 * Unit tests for the typed API client.
 *
 * These run in Vitest's default `node` environment: `src/api/client.ts` uses
 * only `fetch`, `Response`, `Error` and `import.meta.env`, so no DOM shim
 * (jsdom / happy-dom) is required.
 *
 * The default base URL is asserted as `http://localhost:8000` because no
 * `frontend/.env` file exists (only `.env.example`), so
 * `import.meta.env.VITE_API_BASE_URL` is undefined and the built-in default
 * from client.ts applies.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, analyzeUrl, getHistory, getScan } from './client'

const DEFAULT_BASE_URL = 'http://localhost:8000'

/** Build a `Response` with a JSON body. */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** Install a fetch mock that resolves with `response` exactly once. */
function stubFetch(response: Response) {
  const fetchMock = vi.fn((..._args: unknown[]) => Promise.resolve(response))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

/** Install a fetch mock that rejects, simulating an unreachable server. */
function stubFetchRejection(error: unknown = new TypeError('Failed to fetch')) {
  const fetchMock = vi.fn((..._args: unknown[]) => Promise.reject(error))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

/**
 * Await a promise that is expected to reject and return the `ApiError`.
 * Fails the test if the promise resolves instead.
 */
async function captureApiError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError)
    return error as ApiError
  }
  throw new Error('Expected the request to reject, but it resolved.')
}

/** Read the `(url, init)` pair passed to the fetch mock. */
function callArgs(fetchMock: ReturnType<typeof stubFetch>): [string, RequestInit] {
  expect(fetchMock).toHaveBeenCalledTimes(1)
  return fetchMock.mock.calls[0] as [string, RequestInit]
}

const sampleAnalysis = {
  id: 1,
  input_url: 'https://example.com',
  normalized_url: 'https://example.com/',
  scheme: 'https',
  host: 'example.com',
  registrable_domain: 'example.com',
  risk_score: 10,
  risk_label: 'Low',
  findings: [],
  disclaimer: 'Heuristic result, not a security guarantee.',
  created_at: '2026-10-19T00:00:00Z',
  threat_intel: {
    provider: 'virustotal',
    status: 'disabled',
    available: false,
    verdict: 'unavailable',
    message: 'No API key configured.',
    malicious: null,
    suspicious: null,
    harmless: null,
    undetected: null,
    total_engines: null,
    last_analysis_date: null,
    permalink: null,
  },
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
  vi.resetModules()
  vi.restoreAllMocks()
})

describe('analyzeUrl', () => {
  it('returns the parsed JSON body on a successful response', async () => {
    stubFetch(jsonResponse(sampleAnalysis))

    await expect(analyzeUrl('https://example.com')).resolves.toEqual(
      sampleAnalysis,
    )
  })

  it('sends a POST to /api/analyze with the JSON content type and url body', async () => {
    const fetchMock = stubFetch(jsonResponse(sampleAnalysis))

    await analyzeUrl('https://example.com')

    const [url, init] = callArgs(fetchMock)
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/analyze`)
    expect(init.method).toBe('POST')
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' })
    expect(init.body).toBe(JSON.stringify({ url: 'https://example.com' }))
  })

  it('rejects with ApiError when a 2xx response body is not JSON', async () => {
    stubFetch(new Response('<html>index.html</html>', { status: 200 }))

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe(
      'The API returned a response that was not JSON. Check VITE_API_BASE_URL.',
    )
    expect(error.status).toBe(200)
  })
})

describe('HTTP error handling', () => {
  it('uses a string `detail` as the error message and keeps the status', async () => {
    stubFetch(
      jsonResponse(
        { detail: 'Only http and https URLs are supported.' },
        400,
      ),
    )

    const error = await captureApiError(analyzeUrl('not-a-url'))

    expect(error.message).toBe('Only http and https URLs are supported.')
    expect(error.status).toBe(400)
  })

  it('uses the first `msg` of a FastAPI 422 validation error array', async () => {
    stubFetch(
      jsonResponse(
        {
          detail: [
            { loc: ['body', 'url'], msg: 'Field required', type: 'missing' },
            { loc: ['body', 'url'], msg: 'Should be ignored', type: 'value_error' },
          ],
        },
        422,
      ),
    )

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe('Field required')
    expect(error.status).toBe(422)
  })

  it('falls back to the status message when the error body is not JSON', async () => {
    stubFetch(new Response('internal server error', { status: 500 }))

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe('Request failed with status 500.')
    expect(error.status).toBe(500)
  })

  it('falls back to the status message when `detail` is neither a string nor an array', async () => {
    stubFetch(jsonResponse({ detail: 42 }, 503))

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe('Request failed with status 503.')
    expect(error.status).toBe(503)
  })

  it('falls back to the status message when `detail` array entries have no `msg`', async () => {
    stubFetch(jsonResponse({ detail: [{ loc: ['body'] }] }, 400))

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe('Request failed with status 400.')
    expect(error.status).toBe(400)
  })

  it('falls back to the status message for an empty error object', async () => {
    stubFetch(jsonResponse({}, 418))

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe('Request failed with status 418.')
    expect(error.status).toBe(418)
  })
})

describe('network failure', () => {
  it('rejects with ApiError status 0 when fetch itself rejects', async () => {
    stubFetchRejection(new TypeError('Failed to fetch'))

    const error = await captureApiError(analyzeUrl('https://example.com'))

    expect(error.message).toBe(
      'Could not reach the PhishGuard API. Is the backend running?',
    )
    expect(error.status).toBe(0)
  })
})

describe('ApiError', () => {
  it('is an Error subclass carrying the HTTP status', () => {
    const error = new ApiError('boom', 404)

    expect(error).toBeInstanceOf(ApiError)
    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe('ApiError')
    expect(error.status).toBe(404)
    expect(error.message).toBe('boom')
  })

  it('preserves 404 from getScan so the result page can branch on it', async () => {
    stubFetch(jsonResponse({ detail: 'Scan not found.' }, 404))

    const error = await captureApiError(getScan(999999))

    expect(error.status).toBe(404)
    expect(error.message).toBe('Scan not found.')
  })
})

describe('URL construction', () => {
  it('requests /api/history with the default limit of 20', async () => {
    const fetchMock = stubFetch(jsonResponse({ total: 0, items: [] }))

    await getHistory()

    const [url, init] = callArgs(fetchMock)
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/history?limit=20`)
    expect(init.method).toBeUndefined()
    expect(init.body).toBeUndefined()
  })

  it('requests /api/history with an explicit limit', async () => {
    const fetchMock = stubFetch(jsonResponse({ total: 0, items: [] }))

    await getHistory(5)

    expect(callArgs(fetchMock)[0]).toBe(
      `${DEFAULT_BASE_URL}/api/history?limit=5`,
    )
  })

  it('requests /api/history/{id} for a numeric id', async () => {
    const fetchMock = stubFetch(jsonResponse({ id: 7 }))

    await getScan(7)

    expect(callArgs(fetchMock)[0]).toBe(`${DEFAULT_BASE_URL}/api/history/7`)
  })

  it('requests /api/history/{id} for a string id', async () => {
    const fetchMock = stubFetch(jsonResponse({ id: 7 }))

    await getScan('7')

    expect(callArgs(fetchMock)[0]).toBe(`${DEFAULT_BASE_URL}/api/history/7`)
  })
})

describe('base URL configuration', () => {
  it('honours VITE_API_BASE_URL when it is set', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'http://127.0.0.1:9000')
    vi.resetModules()

    const fetchMock = stubFetch(jsonResponse({ total: 0, items: [] }))
    const client = await import('./client')

    await client.getHistory(1)

    expect(callArgs(fetchMock)[0]).toBe('http://127.0.0.1:9000/api/history?limit=1')
  })
})
