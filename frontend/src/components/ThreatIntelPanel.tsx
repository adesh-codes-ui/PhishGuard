import type {
  ThreatIntel,
  ThreatIntelStatus,
  ThreatIntelVerdict,
} from '../api/client'

const statusLabels: Record<ThreatIntelStatus, string> = {
  disabled: 'Not configured',
  found: 'Report found',
  not_found: 'No report',
  rate_limited: 'Rate limited',
  timeout: 'Timed out',
  invalid_key: 'Invalid key',
  error: 'Unavailable',
}

const verdictLabels: Record<ThreatIntelVerdict, string> = {
  malicious: 'Malicious detections',
  suspicious: 'Suspicious detections',
  no_detections: 'No detections',
  unavailable: 'No verdict',
}

// Deliberately neutral for "no_detections": we never render it as "safe".
const verdictStyles: Record<ThreatIntelVerdict, string> = {
  malicious: 'bg-red-500/15 text-red-300 ring-1 ring-inset ring-red-500/30',
  suspicious: 'bg-amber-500/15 text-amber-300 ring-1 ring-inset ring-amber-500/30',
  no_detections:
    'bg-slate-500/15 text-slate-300 ring-1 ring-inset ring-slate-500/30',
  unavailable: 'bg-slate-700/40 text-slate-400 ring-1 ring-inset ring-slate-600/40',
}

function Stat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 text-center">
      <div className="font-mono text-xl text-slate-100">{value ?? '—'}</div>
      <div className="mt-1 text-[0.7rem] uppercase tracking-widest text-slate-500">
        {label}
      </div>
    </div>
  )
}

interface ThreatIntelPanelProps {
  intel: ThreatIntel | null
}

/**
 * Renders external threat-intelligence data separately from the heuristic
 * result. It never restates or overrides the PhishGuard risk score and never
 * claims a URL is safe.
 */
export default function ThreatIntelPanel({ intel }: ThreatIntelPanelProps) {
  if (!intel) {
    return (
      <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-6">
        <h2 className="text-sm font-semibold uppercase tracking-widest text-slate-400">
          Threat intelligence
        </h2>
        <p className="mt-3 text-sm text-slate-400">
          No external threat-intelligence result was recorded for this scan.
        </p>
      </section>
    )
  }

  return (
    <section className="rounded-2xl border border-cyan-500/20 bg-cyan-500/[0.04] p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold uppercase tracking-widest text-cyan-300/80">
          Threat intelligence
        </h2>
        <div className="flex items-center gap-2">
          <span className="rounded-full bg-slate-800/70 px-2.5 py-0.5 text-xs font-medium text-slate-300">
            {intel.provider}
          </span>
          <span className="rounded-full bg-slate-800/70 px-2.5 py-0.5 text-xs font-medium text-slate-400">
            {statusLabels[intel.status]}
          </span>
        </div>
      </div>

      <div className="mt-4">
        <span
          className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold ${verdictStyles[intel.verdict]}`}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
          {verdictLabels[intel.verdict]}
        </span>
      </div>

      <p className="mt-3 text-sm text-slate-300">{intel.message}</p>

      {intel.status === 'found' && (
        <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Stat label="Malicious" value={intel.malicious} />
          <Stat label="Suspicious" value={intel.suspicious} />
          <Stat label="Harmless" value={intel.harmless} />
          <Stat label="Undetected" value={intel.undetected} />
          <Stat label="Engines" value={intel.total_engines} />
        </div>
      )}

      <dl className="mt-4 space-y-1 text-xs text-slate-400">
        {intel.last_analysis_date && (
          <div className="flex justify-between gap-4">
            <dt>Last analyzed</dt>
            <dd className="font-mono text-slate-300">
              {new Date(intel.last_analysis_date).toLocaleString()}
            </dd>
          </div>
        )}
        {intel.permalink && (
          <div className="flex justify-between gap-4">
            <dt>Provider report</dt>
            <dd>
              <a
                href={intel.permalink}
                target="_blank"
                rel="noreferrer noopener"
                className="text-cyan-400 transition-colors hover:text-cyan-300"
              >
                View on VirusTotal ↗
              </a>
            </dd>
          </div>
        )}
      </dl>

      <p className="mt-4 border-t border-slate-800 pt-3 text-xs text-slate-500">
        External reputation data is shown separately from the PhishGuard heuristic
        score and never changes it. No malicious detections does not mean the link
        is safe.
      </p>
    </section>
  )
}
