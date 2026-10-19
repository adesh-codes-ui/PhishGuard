import { Link, Route, Routes, useParams } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import ResultPage from './pages/ResultPage'

/**
 * Remounts ResultPage whenever the scan id changes (for example when the
 * browser back/forward buttons move between two results). A fresh mount
 * guarantees loading, error and not-found state never leak across scans.
 */
function ResultRoute() {
  const { id } = useParams<{ id: string }>()
  return <ResultPage key={id} />
}

function Header() {
  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
        <Link to="/" className="flex items-center gap-3">
          <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-indigo-600 text-lg">
            🛡️
          </span>
          <span className="text-lg font-bold tracking-tight text-white">
            Phish<span className="text-indigo-400">Guard</span>
          </span>
        </Link>
        <span className="hidden text-xs text-slate-500 sm:block">
          Static URL analysis · never fetches links
        </span>
      </div>
    </header>
  )
}

function Footer() {
  return (
    <footer className="mt-16 border-t border-slate-800 py-6">
      <div className="mx-auto max-w-6xl px-4 text-center text-xs text-slate-500">
        PhishGuard is a heuristic tool for education and triage. It cannot confirm
        that a URL is safe.
      </div>
    </footer>
  )
}

export default function App() {
  return (
    <div className="flex min-h-screen flex-col">
      <Header />
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-10">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/result/:id" element={<ResultRoute />} />
          <Route
            path="*"
            element={
              <div className="py-20 text-center">
                <h1 className="text-2xl font-bold text-white">Page not found</h1>
                <Link
                  to="/"
                  className="mt-4 inline-block text-indigo-400 hover:text-indigo-300"
                >
                  Back to dashboard
                </Link>
              </div>
            }
          />
        </Routes>
      </main>
      <Footer />
    </div>
  )
}
