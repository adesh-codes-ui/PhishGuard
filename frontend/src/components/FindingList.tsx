import type { Finding } from '../api/client'
import { severityColor } from '../lib/risk'

interface FindingListProps {
  findings: Finding[]
}

/** Explainable list of reasons behind a risk score. */
export default function FindingList({ findings }: FindingListProps) {
  if (findings.length === 0) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 text-sm text-slate-400">
        No suspicious indicators were detected by the static checks. This does
        not guarantee the link is safe.
      </div>
    )
  }

  return (
    <ul className="space-y-3">
      {findings.map((finding) => (
        <li
          key={finding.code}
          className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 transition-colors hover:border-slate-700"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="font-medium text-slate-100">{finding.title}</p>
              <p className="mt-1 text-sm text-slate-400">{finding.description}</p>
            </div>
            <span
              className={`shrink-0 font-mono text-sm font-semibold ${severityColor(
                finding.severity,
              )}`}
              title={`${finding.severity} severity`}
            >
              +{finding.points}
            </span>
          </div>
        </li>
      ))}
    </ul>
  )
}
