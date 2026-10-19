/**
 * Zero-dependency render smoke tests.
 *
 * These render the real component tree to static HTML with `react-dom/server`,
 * so they need no DOM environment and no extra package. They catch
 * import/render-time failures, route wiring mistakes and accessible-label
 * regressions in the *initial* UI, and they prove the render path performs no
 * I/O.
 *
 * Deliberately NOT covered here: `useEffect` never runs during server
 * rendering, so every page renders its loading branch. Effects, form
 * submission, navigation between scan ids, retry buttons, and the data /
 * error / not-found branches all need a DOM environment plus a React-aware
 * renderer. See `backend/eval/DAY18_REPORT.md` for the proposed dependencies.
 */

import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from './App'

/** Render the whole app (including routing) at `path` to static HTML. */
function renderPath(path: string): string {
  return renderToStaticMarkup(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('dashboard route (/)', () => {
  it('renders the heading, the labelled URL form and the history loading state', () => {
    const html = renderPath('/')

    expect(html).toContain('Is that link a')
    expect(html).toContain('URL to analyze') // sr-only <label for="url">
    expect(html).toContain('Analyze URL')
    expect(html).toContain('Recent scans')
    expect(html).toContain('Loading history') // effects do not run in SSR
  })

  it('has no alert region and no error text before anything fails', () => {
    const html = renderPath('/')

    expect(html).not.toContain('role="alert"')
  })

  it('exposes the loading state to assistive technology (role=status)', () => {
    expect(renderPath('/')).toContain('role="status"')
  })

  it('disables the submit button until a URL is entered', () => {
    expect(renderPath('/')).toContain('disabled=""')
  })
})

describe('result route (/result/:id)', () => {
  it('renders the loading state for a scan id', () => {
    expect(renderPath('/result/1')).toContain('Loading analysis')
  })

  it('renders the back link to the dashboard', () => {
    expect(renderPath('/result/1')).toContain('New scan')
  })
})

describe('unknown route', () => {
  it('renders the not-found page with a link home', () => {
    const html = renderPath('/definitely-not-a-route')

    expect(html).toContain('Page not found')
    expect(html).toContain('Back to dashboard')
  })
})

describe('render purity', () => {
  it('performs no fetch while rendering any route', () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve(new Response('{}', { status: 200 })),
    )
    vi.stubGlobal('fetch', fetchMock)

    renderPath('/')
    renderPath('/result/1')
    renderPath('/result/999999')
    renderPath('/nope')

    expect(fetchMock).not.toHaveBeenCalled()
  })
})
