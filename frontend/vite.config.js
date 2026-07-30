import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The backend serves the built SPA from `frontend/dist` at `/` and its bundled
// assets at `/assets/*` (see app/main.py). Keep Vite's default `base: '/'` so
// index.html references assets at absolute `/assets/...`.
//
// In dev, `npm run dev` runs Vite on its own port; proxy the API surface to the
// Flask backend on :8080 so same-origin relative fetches (e.g. `/api/findings`)
// work without CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8080', changeOrigin: true },
      '/metrics': { target: 'http://localhost:8080', changeOrigin: true },
      '/healthz': { target: 'http://localhost:8080', changeOrigin: true },
      '/readyz': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
});
