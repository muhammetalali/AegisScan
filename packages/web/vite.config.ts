import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Django owns authentication, user management and durable application resources.
      '/api/v1/auth': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/users': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/projects': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/assets': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/scans': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/vulnerabilities': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/reports': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/compliance': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/audit': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/dashboard': { target: 'http://localhost:8000', changeOrigin: true },
      '/api/v1/knowledge': { target: 'http://localhost:8000', changeOrigin: true },
      // FastAPI owns operational and assurance endpoints that are not durable CRUD.
      '/api': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8001',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router-dom'],
          charts: ['echarts', 'echarts-for-react'],
          ui: ['framer-motion', 'lucide-react', 'sonner'],
          forms: ['react-hook-form', '@hookform/resolvers', 'zod'],
          editor: ['@monaco-editor/react'],
        },
      },
    },
  },
})
