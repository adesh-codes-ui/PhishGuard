import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { analyzeUrl, getHistory, type ScanSummary } from '../api/client'
import HistoryList from '../components/HistoryList'
import UrlForm from '../components/UrlForm'

const FEATURES = [
  {
    title: 'Static, explainable checks',
    body: 'HTTPS usage, IP hosts, brand impersonation, punycode, suspicious keywords and URL structure — each with a plain-English reason.',
  },
  {
    title: 'Never visits your link',
    body: 'PhishGuard analyzes the URL string only. It never fetches or renders the destination, so you cannot be exposed to a live phishing page.',
  },
  {
    title: '0–100 risk score',
    body: 'Weighted findings combine into a single score with a Low, Medium, High or Critical label and a full breakdown.',
  },
]

export default function Dashboard() {
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [history, setHistory] = useState<ScanSummary[]>([])
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState<string | null>(null)

  // Data load expressed as a promise chain: every setState runs inside a
  // .then/.catch callback, never synchronously during the mount effect, so
  // `set-state-in-effect` does not fire. Loading/error state starts from the
  // useState defaults and is reset by the retry event handler.
  const loadHistory = useCallback(
    () =>
      getHistory(15)
        .then((data) => {
          setHistory(data.items)
          setHistoryLoading(false)
        })
        .catch((err: unknown) => {
          setHistoryError(
            err instanceof Error ? err.message : 'Failed to load history.',
          )
          setHistoryLoading(false)
        }),
    [],
  )

  useEffect(() => {
    void loadHistory()
  }, [loadHistory])

  async function handleAnalyze(url: string) {
    setLoading(true)
    setError(null)
    try {
      const analysis = await analyzeUrl(url)
      navigate(`/result/${analysis.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-10">
      <section className="text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3 py-1 text-xs font-medium text-indigo-300">
          <span className="h-1.5 w-1.5 rounded-full bg-indigo-400" aria-hidden="true" />
          Explainable phishing URL analysis
        </span>
        <h1 className="mt-5 text-4xl font-bold tracking-tight text-white sm:text-5xl">
          Is that link a <span className="text-red-400">phishing</span> attempt?
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-slate-400">
          Paste a URL to inspect it for common phishing signals. PhishGuard never
          opens the link — it only reads the URL string.
        </p>
      </section>

      <section className="mx-auto max-w-3xl">
        <UrlForm onSubmit={handleAnalyze} loading={loading} />

        {error && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-300"
          >
            <span className="mt-0.5" aria-hidden="true">
              ⚠
            </span>
            <span>{error}</span>
          </div>
        )}
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
        {FEATURES.map((feature) => (
          <div
            key={feature.title}
            className="rounded-2xl border border-slate-800 bg-slate-900/40 p-5"
          >
            <h3 className="font-semibold text-slate-100">{feature.title}</h3>
            <p className="mt-2 text-sm text-slate-400">{feature.body}</p>
          </div>
        ))}
      </section>

      <HistoryList
        items={history}
        loading={historyLoading}
        error={historyError}
        onRetry={() => {
          setHistoryLoading(true)
          setHistoryError(null)
          void loadHistory()
        }}
      />
    </div>
  )
}
