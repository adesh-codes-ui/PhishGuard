import type { RiskLabel } from '../api/client'
import { riskThemes } from '../lib/risk'

interface RiskGaugeProps {
  score: number
  label: RiskLabel
}

/** Circular 0–100 risk gauge rendered with SVG. */
export default function RiskGauge({ score, label }: RiskGaugeProps) {
  const theme = riskThemes[label]
  const radius = 70
  const circumference = 2 * Math.PI * radius
  const clamped = Math.max(0, Math.min(100, score))
  const dash = (clamped / 100) * circumference

  return (
    <div className={`relative h-44 w-44 rounded-full ${theme.ring} ring-1`}>
      {/* Decorative: the numeric score and label are rendered as text below. */}
      <svg viewBox="0 0 160 160" className="h-full w-full -rotate-90" aria-hidden="true">
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="#1e293b"
          strokeWidth="12"
        />
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke={theme.stroke}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference - dash}`}
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-mono text-4xl font-bold ${theme.text}`}>
          {clamped}
        </span>
        <span className="text-xs uppercase tracking-widest text-slate-400">
          risk score
        </span>
      </div>
    </div>
  )
}
