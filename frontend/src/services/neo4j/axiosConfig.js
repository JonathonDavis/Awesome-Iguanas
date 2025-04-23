import axios from 'axios';

// Create axios instances with appropriate configurations
export const apiClient = axios.create({
  timeout: 90000, // Increased to 90 seconds for better reliability
});

// Create a specific client for Ollama API calls
export const ollamaClient = axios.create({
  // Use relative URL to ensure it works with the nginx proxy
  baseURL: '/api', // This will use the current domain with /api path
  timeout: 180000, // 3 minutes timeout for LLM operations
  headers: {
    'Content-Type': 'application/json',
  },
  // Add these settings to avoid connection issues
  maxContentLength: Infinity,
  maxBodyLength: Infinity
});

// Setup function to configure axios client
export function setupAxiosClient() {
  // Add a retry interceptor
  apiClient.interceptors.response.use(null, async (error) => {
    const { config } = error;
    
    // If config doesn't exist or we've already retried 3 times, reject
    if (!config || config.__retryCount >= 3) {
      return Promise.reject(error);
    }
    
    // Set retry count
    config.__retryCount = config.__retryCount || 0;
    config.__retryCount++;
    
    // Calculate backoff delay - 2^retry * 1000 milliseconds
    const backoff = Math.pow(2, config.__retryCount) * 1000;
    console.log(`Request failed, retrying in ${backoff}ms... (Attempt ${config.__retryCount}/3)`);
    
    // Wait for the backoff period
    await new Promise(resolve => setTimeout(resolve, backoff));
    
    // Return the promise for the retry
    return apiClient(config);
  });

  // Apply enhanced retry logic to Ollama client
  ollamaClient.interceptors.response.use(null, async (error) => {
    const { config } = error;
    
    if (!config || config.__retryCount >= 3) {  // Increased to 3 retries
      return Promise.reject(error);
    }
    
    config.__retryCount = config.__retryCount || 0;
    config.__retryCount++;
    
    const backoff = Math.pow(2, config.__retryCount) * 1500; // Increased backoff time
    console.log(`Ollama API request failed, retrying in ${backoff}ms... (Attempt ${config.__retryCount}/3)`);
    
    await new Promise(resolve => setTimeout(resolve, backoff));
    
    return ollamaClient(config);
  });

  // Add request interceptor to handle connection issues
  ollamaClient.interceptors.request.use(
    (config) => {
      // Log requests for debugging
      console.log(`Making request to ${config.url}`);
      return config;
    },
    (error) => {
      console.error('Request error:', error);
      return Promise.reject(error);
    }
  );

  return { apiClient, ollamaClient };
}

// Initialize both clients immediately
setupAxiosClient();

export default apiClient;
