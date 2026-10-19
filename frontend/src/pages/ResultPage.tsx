import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ApiError, getScan, type ScanDetail } from '../api/client'
import FindingList from '../components/FindingList'
import RiskBadge from '../components/RiskBadge'
import RiskGauge from '../components/RiskGauge'
import Spinner from '../components/Spinner'
import ThreatIntelPanel from '../components/ThreatIntelPanel'

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5 border-b border-slate-800/70 py-2 last:border-b-0 sm:flex-row sm:items-center sm:justify-between">
      <dt className="text-xs uppercase tracking-widest text-slate-500">{label}</dt>
      <dd className="break-all font-mono text-sm text-slate-200">{value}</dd>
    </div>
  )
}

export default function ResultPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<ScanDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notFound, setNotFound] = useState(false)

  // Data load expressed as a promise chain: every setState runs inside a
  // .then/.catch/.finally callback, never synchronously during the mount
  // effect, so `set-state-in-effect` does not fire. A fresh mount already
  // starts with loading=true / error=null / notFound=false, and the ResultRoute
  // key remounts this page when the scan id changes. The retry button resets
  // loading and error itself before reloading.
  const load = useCallback(() => {
    if (!id) return Promise.resolve()
    return getScan(id)
      .then((data) => {
        setScan(data)
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 404) {
          setNotFound(true)
        } else {
          setError(
            err instanceof Error ? err.message : 'Failed to load result.',
          )
        }
      })
      .finally(() => {
        setLoading(false)
      })
  }, [id])

  useEffect(() => {
    void load()
  }, [load])

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Link
        to="/"
        className="inline-flex items-center gap-1 text-sm text-indigo-400 transition-colors hover:text-indigo-300"
      >
        ← New scan
      </Link>

      {loading && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-10 text-center">
          <Spinner label="Loading analysis…" />
        </div>
      )}

      {!loading && notFound && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-8 text-center">
          <h2 className="text-lg font-semibold text-slate-100">Scan not found</h2>
          <p className="mt-2 text-sm text-slate-400">
            This scan id does not exist in the history.
          </p>
          <Link
            to="/"
            className="mt-4 inline-block rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
          >
            Back to dashboard
          </Link>
        </div>
      )}

      {!loading && error && (
        <div
          role="alert"
          className="rounded-2xl border border-red-500/30 bg-red-500/10 p-6 text-sm text-red-300"
        >
          <p>{error}</p>
          <button
            type="button"
            onClick={() => {
              setLoading(true)
              setError(null)
              void load()
            }}
            className="mt-3 rounded-lg border border-red-500/40 px-3 py-1.5 text-xs font-medium text-red-200 hover:bg-red-500/10"
          >
            Retry
          </button>
        </div>
      )}

      {!loading && !error && !notFound && scan && (
        <>
          <section className="flex flex-col items-center gap-6 rounded-2xl border border-slate-800 bg-slate-900/40 p-6 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0 text-center sm:text-left">
              <RiskBadge label={scan.risk_label} score={scan.risk_score} />
              <h1 className="mt-3 break-all font-mono text-lg text-slate-100">
                {scan.host}
              </h1>
              <p className="mt-1 break-all text-sm text-slate-400">
                {scan.normalized_url}
              </p>
            </div>
            <RiskGauge score={scan.risk_score} label={scan.risk_label} />
          </section>

          <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6">
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-widest text-slate-400">
              Details
            </h2>
            <dl className="text-sm">
              <DetailRow label="Submitted" value={scan.url} />
              <DetailRow label="Normalized" value={scan.normalized_url} />
              <DetailRow label="Scheme" value={scan.scheme} />
              <DetailRow label="Host" value={scan.host} />
              <DetailRow label="Registered domain" value={scan.registrable_domain} />
              <DetailRow
                label="Scanned at"
                value={new Date(scan.created_at).toLocaleString()}
              />
            </dl>
          </section>

          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-widest text-slate-400">
              Why this score ({scan.findings.length} finding
              {scan.findings.length === 1 ? '' : 's'})
            </h2>
            <FindingList findings={scan.findings} />
          </section>

          <ThreatIntelPanel intel={scan.threat_intel} />

          <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
            <strong className="font-semibold">Note:</strong> This result is based on
            static heuristics only and is not proof that a URL is safe or unsafe.
            PhishGuard never visits submitted links. Always verify a site&apos;s
            identity through official channels before entering credentials.
          </div>
        </>
      )}
    </div>
  )
}
