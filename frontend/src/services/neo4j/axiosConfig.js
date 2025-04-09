import axios from 'axios';

// Create an axios instance with increased timeout and retry configuration
export const apiClient = axios.create({
  timeout: 60000, // Increased to 60 seconds (from 30s)
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

  return apiClient;
}

export default apiClient; 