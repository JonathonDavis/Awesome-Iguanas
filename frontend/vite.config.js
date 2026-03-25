import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Load env for the active mode (development/production/etc)
  const env = loadEnv(mode, process.cwd(), '');
  const apiKey = env.VITE_NIST_API_KEY;

  return {
    plugins: [vue()],
    server: {
      proxy: {
        // Proxy requests to NVD API to avoid CORS issues
        '/api/proxy/nvd/cves': {
          target: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
          changeOrigin: true,
          secure: true,
          rewrite: (path) => path.replace(/^\/api\/proxy\/nvd\/cves/, ''),
          configure: (proxy) => {
            // Add the API key from environment to all proxy requests
            proxy.on('proxyReq', (proxyReq) => {
              if (apiKey) {
                proxyReq.setHeader('apiKey', apiKey);
                console.log('Added API key to NVD API request');
              } else {
                console.warn('No API key found for NVD API requests');
              }
            });
          },
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
          }
        },

        // Proxy OSV API (public) to avoid browser CORS issues
        '/api/proxy/osv': {
          target: 'https://api.osv.dev',
          changeOrigin: true,
          secure: true,
          rewrite: (path) => path.replace(/^\/api\/proxy\/osv/, '')
        },

        // RepairGPT API (local dev convenience)
        '/api/repair': {
          target: 'http://localhost:5000',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/api\/repair/, '')
        }
      },
      host: true,
      allowedHosts: ['iguanasgpt.space', 'www.iguanasgpt.space', 'awesome-iguanas.com', 'www.awesome-iguanas.com']
    },
    preview: {
      host: true,
      allowedHosts: ['iguanasgpt.space', 'www.iguanasgpt.space', 'awesome-iguanas.com', 'www.awesome-iguanas.com']
    }
  };
});