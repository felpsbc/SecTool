import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Repassa /api para a API do OWASP-Scan (python -m owaspscan.api),
    // evitando CORS em desenvolvimento. Em producao use VITE_API_URL.
    proxy: {
      '/api': {
        target: process.env.OWASPSCAN_API || 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (caminho) => caminho.replace(/^\/api/, ''),
      },
    },
  },
})
