/**
 * Typed client for the PhishGuard FastAPI backend.
 *
 * The base URL is read from VITE_API_BASE_URL (see .env.example) and defaults
 * to the local development server. No secrets are stored here.
 */

export type RiskLabel = 'Low' | 'Medium' | 'High' | 'Critical'

export interface Finding {
  code: string
  title: string
  description: string
  points: number
  severity: string
}

/**
 * External threat-intelligence status reported by the backend.
 * This is NOT part of the PhishGuard heuristic risk score.
 */
export type ThreatIntelStatus =
  | 'disabled'
  | 'found'
  | 'not_found'
  | 'rate_limited'
  | 'timeout'
  | 'invalid_key'
  | 'error'

/** Provider-only verdict. "no_detections" explicitly does NOT mean "safe". */
export type ThreatIntelVerdict =
  | 'malicious'
  | 'suspicious'
  | 'no_detections'
  | 'unavailable'

export interface ThreatIntel {
  provider: string
  status: ThreatIntelStatus
  available: boolean
  verdict: ThreatIntelVerdict
  message: string
  malicious: number | null
  suspicious: number | null
  harmless: number | null
  undetected: number | null
  total_engines: number | null
  last_analysis_date: string | null
  permalink: string | null
}

export interface Analysis {
  id: number
  input_url: string
  normalized_url: string
  scheme: string
  host: string
  registrable_domain: string
  risk_score: number
  risk_label: RiskLabel
  findings: Finding[]
  disclaimer: string
  created_at: string
  threat_intel: ThreatIntel
}

export interface ScanSummary {
  id: number
  url: string
  normalized_url: string
  host: string
  risk_score: number
  risk_label: RiskLabel
  created_at: string
}

export interface ScanDetail extends ScanSummary {
  scheme: string
  registrable_domain: string
  findings: Finding[]
  threat_intel: ThreatIntel | null
}

export interface HistoryResponse {
  total: number
  items: ScanSummary[]
}

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

/** Error carrying the HTTP status and a human-readable message. */
export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { 'Content-Type': 'application/json' },
      ...init,
    })
  } catch {
    throw new ApiError(
      'Could not reach the PhishGuard API. Is the backend running?',
      0,
    )
  }

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}.`
    try {
      const body = await response.json()
      if (body && typeof body.detail === 'string') {
        detail = body.detail
      } else if (Array.isArray(body?.detail) && body.detail[0]?.msg) {
        // FastAPI validation errors.
        detail = body.detail[0].msg
      }
    } catch {
      // Keep the default message if the body is not JSON.
    }
    throw new ApiError(detail, response.status)
  }

  // A 2xx body that is not JSON means the API base URL is mis-routed (for
  // example a reverse proxy/SPA fallback answering a mis-prefixed /api path
  // with index.html). Surface a clear message instead of leaking a raw
  // SyntaxError such as "Unexpected token '<'" into the error banner.
  try {
    return (await response.json()) as T
  } catch {
    throw new ApiError(
      'The API returned a response that was not JSON. Check VITE_API_BASE_URL.',
      response.status,
    )
  }
}

export function analyzeUrl(url: string): Promise<Analysis> {
  return request<Analysis>('/api/analyze', {
    method: 'POST',
    body: JSON.stringify({ url }),
  })
}

export function getHistory(limit = 20): Promise<HistoryResponse> {
  return request<HistoryResponse>(`/api/history?limit=${limit}`)
}

export function getScan(id: number | string): Promise<ScanDetail> {
  return request<ScanDetail>(`/api/history/${id}`)
}
