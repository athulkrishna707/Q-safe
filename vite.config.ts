import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

// Q-SAFE Python backend URL (running on port 8000)
const QSAFE_BACKEND = 'http://localhost:8000';

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâ€”file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
      // Proxy all backend API calls to the Q-SAFE Python gateway (port 8000)
      proxy: {
        '/auth': { target: QSAFE_BACKEND, changeOrigin: true },
        '/bank': { target: QSAFE_BACKEND, changeOrigin: true },
        '/telemetry': { target: QSAFE_BACKEND, changeOrigin: true },
        '/sessions': { target: QSAFE_BACKEND, changeOrigin: true },
        '/simulator': { target: QSAFE_BACKEND, changeOrigin: true },
        '/api': { target: QSAFE_BACKEND, changeOrigin: true },
        '/ws': {
          target: QSAFE_BACKEND,
          changeOrigin: true,
          ws: true,  // Enable WebSocket proxying
        },
      },
    },
  };
});
