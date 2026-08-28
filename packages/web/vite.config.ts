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
      // Django owns authentication and user-management APIs.
      '/api/v1/auth': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/v1/users': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/api/v1/reports': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      // FastAPI owns the operational/assurance API surface.
      '/api': {
        target: 'http://localhost:8001',
        changeOrigin: true,
      },
      // All WebSocket endpoints are served by FastAPI.
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
