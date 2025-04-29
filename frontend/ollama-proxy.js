const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

const app = express();
const port = process.env.PROXY_PORT || 3000;

// Get the Ollama API URL from environment variable
const ollamaApiUrl = process.env.INTERNAL_OLLAMA_API_URL || process.env.OLLAMA_API_URL || 'http://host.docker.internal:11434' || 'http://127.0.0.1:11434';
console.log(`[OLLAMA-PROXY] Configured to use Ollama at: ${ollamaApiUrl}`);

// Enable CORS for all routes with more specific configuration
app.use(cors({
  origin: ['https://awesome-iguanas.com', 'http://awesome-iguanas.com', 'http://localhost:5173', 'https://localhost:5173', '*'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

// Log requests
app.use((req, res, next) => {
  console.log(`[OLLAMA-PROXY] ${req.method} ${req.url}`);
  next();
});

// Options handling for CORS preflight
app.options('*', cors());

// Proxy all requests to Ollama API
const proxyOptions = {
  target: ollamaApiUrl,
  changeOrigin: true,
  pathRewrite: {
    '^/api': '/', // Remove '/api' prefix when forwarding
  },
  headers: {
    // Add custom headers that Ollama might expect
    'Origin': ollamaApiUrl,
    'Host': new URL(ollamaApiUrl).host
  },
  onProxyReq: (proxyReq, req, res) => {
    // Log detailed info about the request
    console.log(`[OLLAMA-PROXY] Forwarding ${req.method} ${req.path} to ${ollamaApiUrl}`);
    
    // Add Origin header to all requests going to Ollama
    proxyReq.setHeader('Origin', ollamaApiUrl);
    
    if (req.body) {
      try {
        // Try to log the model being used if possible
        const model = req.body.model || 'unknown';
        console.log(`[OLLAMA-PROXY] Request for model: ${model}`);
      } catch (e) {
        // Don't fail if we can't parse the body
      }
    }
  },
  onProxyRes: (proxyRes, req, res) => {
    // Log the proxy response
    console.log(`[OLLAMA-PROXY] Received ${proxyRes.statusCode} from Ollama API`);
    
    // Override CORS headers in the response to allow our domain
    proxyRes.headers['Access-Control-Allow-Origin'] = '*';
    proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
    proxyRes.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With';
  },
  onError: (err, req, res) => {
    console.error(`[OLLAMA-PROXY] Proxy Error: ${err.message}`);
    
    // Send an error response back to the client
    res.status(500).json({
      error: `Failed to connect to Ollama API: ${err.message}`,
      proxy: 'ollama-proxy',
      targetUrl: ollamaApiUrl
    });
  }
};

// Apply the proxy middleware
app.use('/', createProxyMiddleware(proxyOptions));

// Start the server
app.listen(port, '0.0.0.0', () => {
  console.log(`[OLLAMA-PROXY] Server running at http://0.0.0.0:${port}`);
  console.log(`[OLLAMA-PROXY] Forwarding to ${ollamaApiUrl}`);
});