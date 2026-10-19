/** Small accessible loading spinner. */
export default function Spinner({ label = 'Loading' }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2" role="status" aria-live="polite">
      <span
        className="h-4 w-4 animate-[pg-spin_0.7s_linear_infinite] rounded-full border-2 border-slate-500 border-t-transparent"
        aria-hidden="true"
      />
      <span className="text-sm text-slate-400">{label}</span>
    </span>
  )
}
