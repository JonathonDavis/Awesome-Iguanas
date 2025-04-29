import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import dotenv from 'dotenv'
import path from 'path'

// Load environment variables
dotenv.config()

// Get the API key from environment
const apiKey = process.env.VITE_NIST_API_KEY

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      // Remove the chart.js alias completely
    }
  },
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
      },
      // Proxy API requests to the Ollama API
      '/ollama-api': {
        target: 'http://localhost:11434',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/ollama-api/, ''),
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            console.log('Proxy error:', err);
          });
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            console.log('Sending Request to Ollama API:', req.method, req.url);
          });
          proxy.on('proxyRes', (proxyRes, req, _res) => {
            console.log('Received Response from Ollama API:', proxyRes.statusCode, req.url);
          });
        },
      },
      // Add direct-ollama endpoint for development mode
      '/api/direct-ollama': {
        target: 'http://localhost:11434',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/direct-ollama/, ''),
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            console.log('Direct Ollama Proxy error:', err);
          });
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            // Set the origin header to make Ollama accept the request
            proxyReq.setHeader('Origin', 'http://localhost:11434');
            // Log the request for debugging
            console.log('Sending Request to Direct Ollama API:', req.method, req.url);
          });
          proxy.on('proxyRes', (proxyRes, req, _res) => {
            console.log('Received Response from Direct Ollama API:', proxyRes.statusCode, req.url);
          });
        },
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
        }
      }
    },
  }
})
