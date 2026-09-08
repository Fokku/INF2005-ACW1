import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Everything under /api goes to the FastAPI backend, so the browser only
    // ever talks to one origin and CORS never enters the picture.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    // FastAPI serves this directory in demo/marker mode (see backend/app/main.py).
    outDir: 'dist',
  },
})
