import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    // Raise the warning threshold slightly — individual chunks are fine up to 600 kB.
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        // Split large vendor libraries into separately-cached chunks so users
        // only re-download the chunk that actually changed after an update.
        // Split large vendor libraries into separately-cached chunks so users
        // only re-download the chunk that actually changed after an update.
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (id.includes('/react-dom/') || id.includes('/react/') || id.includes('/react-router'))
            return 'vendor-react'
          if (id.includes('/recharts/') || id.includes('/victory-') || id.includes('/d3-'))
            return 'vendor-charts'
          if (id.includes('/radix-ui/') || id.includes('@radix-ui/'))
            return 'vendor-radix'
          if (id.includes('/@react-oauth/'))
            return 'vendor-oauth'
          if (id.includes('/date-fns/'))
            return 'vendor-date'
          if (id.includes('/lucide-react/'))
            return 'vendor-icons'
        },
      },
    },
  },
  // FIX: proxy all API calls through Vite in development.
  // This avoids CORS entirely — the browser talks to localhost:5173,
  // Vite forwards to localhost:8000 server-side where CORS doesn't apply.
  // The CORSMiddleware in main.py can stay as a production/non-proxy fallback.
  server: {
    proxy: {
      // Proxy API routes to the backend.
      // IMPORTANT: '/auth/github/callback' is a FRONTEND route (React Router page).
      // We must NOT proxy it — GitHub redirects the browser there after OAuth.
      // The bypass function returns null → Vite serves index.html → React Router handles it.
      '/auth': {
        target: 'http://localhost:8000',
        bypass(req) {
          // Let the frontend React Router handle the GitHub callback page
          if (req.url?.startsWith('/auth/github/callback')) return req.url
          return null  // null = proxy to backend
        },
      },
      '/apps': 'http://localhost:8000',
      '/admin': 'http://localhost:8000',
      '/reports': 'http://localhost:8000',
      '/contact': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
})