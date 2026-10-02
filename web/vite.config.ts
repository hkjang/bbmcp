import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The build output is embedded into the Go binary (internal/webui/dist), so a
// single container image carries the whole service for an air-gapped install.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:18411',
      '/auth': 'http://localhost:18411',
      '/mcp': 'http://localhost:18411',
      '/healthz': 'http://localhost:18411',
    },
  },
})
