import { Link } from 'react-router-dom'
import type { ScanSummary } from '../api/client'
import RiskBadge from './RiskBadge'
import Spinner from './Spinner'

interface HistoryListProps {
  items: ScanSummary[]
  loading: boolean
  error: string | null
  onRetry: () => void
}

function formatTime(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString()
}

/** Recent scans, with loading / error / empty states. */
export default function HistoryList({
  items,
  loading,
  error,
  onRetry,
}: HistoryListProps) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-widest text-slate-400">
          Recent scans
        </h2>
        <button
          type="button"
          onClick={onRetry}
          className="text-xs text-indigo-400 transition-colors hover:text-indigo-300"
        >
          Refresh
        </button>
      </div>

      {loading && (
        <div className="py-6 text-center">
          <Spinner label="Loading history…" />
        </div>
      )}

      {!loading && error && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
        >
          {error}
        </div>
      )}

      {!loading && !error && items.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-sm text-slate-500">
          No scans yet. Analyze a URL to build your history.
        </div>
      )}

      {!loading && !error && items.length > 0 && (
        <ul className="space-y-2">
          {items.map((item) => (
            <li key={item.id}>
              <Link
                to={`/result/${item.id}`}
                className="flex items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2.5 transition-colors hover:border-indigo-500/40 hover:bg-slate-900"
              >
                <span className="min-w-0">
                  <span className="block truncate font-mono text-sm text-slate-200">
                    {item.host}
                  </span>
                  <span className="block text-xs text-slate-500">
                    {formatTime(item.created_at)}
                  </span>
                </span>
                <RiskBadge label={item.risk_label} score={item.risk_score} size="sm" />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
