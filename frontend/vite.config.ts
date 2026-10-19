import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Local-only demo: bind the dev server to the loopback interface so it is
    // never reachable from another machine (the CLI `--host` flag still
    // overrides it).
    //
    // `127.0.0.1` rather than `localhost` on purpose. `localhost` resolves to
    // IPv6 `::1` here, which the dev server would bind exclusively, leaving
    // `http://127.0.0.1:5173` unreachable even though the backend allow-lists
    // that origin. Binding the IPv4 loopback puts the dev server on the same
    // address family as uvicorn (`--host 127.0.0.1`); browsers still reach it
    // via `http://localhost:5173`, so the documented URL keeps working.
    host: '127.0.0.1',
    port: 5173,
  },
})
