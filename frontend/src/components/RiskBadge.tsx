import type { RiskLabel } from '../api/client'
import { riskThemes } from '../lib/risk'

interface RiskBadgeProps {
  label: RiskLabel
  score?: number
  size?: 'sm' | 'md'
}

export default function RiskBadge({ label, score, size = 'md' }: RiskBadgeProps) {
  const theme = riskThemes[label]
  const padding = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm'

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full font-semibold ${padding} ${theme.badge}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden="true" />
      {label}
      {typeof score === 'number' && (
        <span className="font-mono text-[0.75em] opacity-80">{score}/100</span>
      )}
    </span>
  )
}
