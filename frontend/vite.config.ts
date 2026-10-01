import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/agent': {
        target: process.env.VULNSCOUT_AGENT_API_URL || 'http://127.0.0.1:7275',
      },
    },
  },
  build: {
    outDir: '../src/static',
    emptyOutDir: true,
  }
})
