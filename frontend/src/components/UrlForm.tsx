import { useState, type FormEvent } from 'react'
import Spinner from './Spinner'

interface UrlFormProps {
  onSubmit: (url: string) => void
  loading: boolean
}

const EXAMPLES = [
  'https://www.example.com/login',
  'http://paypal.com.secure-login.evil.net/verify',
  'http://192.168.0.1/account',
]

/** URL entry form with a loading state and quick examples. */
export default function UrlForm({ onSubmit, loading }: UrlFormProps) {
  const [value, setValue] = useState('')

  function handleSubmit(event: FormEvent) {
    event.preventDefault()
    const trimmed = value.trim()
    if (!trimmed || loading) return
    onSubmit(trimmed)
  }

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <label htmlFor="url" className="sr-only">
        URL to analyze
      </label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          id="url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          maxLength={2048}
          placeholder="https://example.com/login"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          disabled={loading}
          className="w-full rounded-xl border border-slate-700 bg-slate-900/80 px-4 py-3 font-mono text-sm text-slate-100 placeholder:text-slate-500 focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/30 disabled:opacity-60"
        />
        <button
          type="submit"
          disabled={loading || value.trim().length === 0}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-600 px-6 py-3 font-semibold text-white transition-colors hover:bg-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-400 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? <Spinner label="Analyzing…" /> : 'Analyze URL'}
        </button>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
        <span>Try:</span>
        {EXAMPLES.map((example) => (
          <button
            key={example}
            type="button"
            onClick={() => setValue(example)}
            disabled={loading}
            className="rounded-full border border-slate-800 bg-slate-900/60 px-3 py-1 font-mono text-[0.7rem] text-slate-400 transition-colors hover:border-slate-700 hover:text-slate-200 disabled:opacity-50"
          >
            {example}
          </button>
        ))}
      </div>
    </form>
  )
}
