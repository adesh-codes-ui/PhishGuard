import type { RiskLabel } from '../api/client'

/** Central place for the visual language of each risk label. */
export interface RiskTheme {
  badge: string
  ring: string
  text: string
  stroke: string
  glow: string
}

export const riskThemes: Record<RiskLabel, RiskTheme> = {
  Low: {
    badge: 'bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30',
    ring: 'bg-emerald-500/10 ring-emerald-500/20',
    text: 'text-emerald-400',
    stroke: '#34d399',
    glow: 'shadow-emerald-500/20',
  },
  Medium: {
    badge: 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30',
    ring: 'bg-amber-500/10 ring-amber-500/20',
    text: 'text-amber-400',
    stroke: '#fbbf24',
    glow: 'shadow-amber-500/20',
  },
  High: {
    badge: 'bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/30',
    ring: 'bg-orange-500/10 ring-orange-500/20',
    text: 'text-orange-400',
    stroke: '#fb923c',
    glow: 'shadow-orange-500/20',
  },
  Critical: {
    badge: 'bg-red-500/15 text-red-300 ring-1 ring-red-500/30',
    ring: 'bg-red-500/10 ring-red-500/20',
    text: 'text-red-400',
    stroke: '#f87171',
    glow: 'shadow-red-500/20',
  },
}

export function severityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-red-400'
    case 'high':
      return 'text-orange-400'
    case 'medium':
      return 'text-amber-400'
    case 'low':
      return 'text-sky-400'
    default:
      return 'text-slate-400'
  }
}
