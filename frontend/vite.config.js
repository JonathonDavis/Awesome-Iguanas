import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  build: {
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'd3': ['d3'],
          'vis-network': ['vis-network']
        }
      }
    }
  },
  define: {
    'process.env': {}
  }
})
