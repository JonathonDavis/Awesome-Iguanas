import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import dotenv from 'dotenv'
// Load environment variables
dotenv.config()
// Get the API key from environment
const apiKey = process.env.VITE_NIST_API_KEY
// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      // Proxy requests to NVD API to avoid CORS issues
      '/api/proxy/nvd/cves': {
        target: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        changeOrigin: true,
        secure: true,
        rewrite: (path) => path.replace(/^\/api\/proxy\/nvd\/cves/, ''),
        configure: (proxy, options) => {
          // Add the API key from environment to all proxy requests
          proxy.on('proxyReq', (proxyReq, req, res) => {
            if (apiKey) {
              proxyReq.setHeader('apiKey', apiKey);
              console.log('Added API key to NVD API request');
            } else {
              console.warn('No API key found for NVD API requests');
            }
          });
        },
        headers: {
          // Set additional headers for the request
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        }
      }
    },
    host: true,
    allowedHosts: ['iguanasgpt.space', 'www.iguanasgpt.space']
  },
  preview: {
    host: true,
    allowedHosts: ['iguanasgpt.space', 'www.iguanasgpt.space']
  }
})