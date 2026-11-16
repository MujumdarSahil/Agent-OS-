import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // AGENTOS_API_TARGET lets the e2e suite point the dev proxy at its own backend port.
      // ws: true carries the /api/v2 run-event WebSocket (token subprotocol) through the proxy.
      '/api': {
        target: process.env.AGENTOS_API_TARGET || 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
      },
    },
  },
})
