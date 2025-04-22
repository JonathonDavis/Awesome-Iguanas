import axios from 'axios'

// Constants for severity mapping
const SEVERITY_LEVELS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'NONE'
}

class NVDService {
  constructor() {
    this.apiKey = import.meta.env.VITE_NIST_API_KEY
    
    // Determine if we're using the proxy or direct API based on environment
    const useProxy = true // Always use proxy to avoid CORS issues
    
    // Use proxy endpoint to avoid CORS issues
    this.apiBaseUrl = useProxy 
      ? '/api/proxy/nvd/cves' // This will be handled by our backend proxy
      : 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    console.log(`NVD Service initialized using ${useProxy ? 'proxy endpoint' : 'direct API'}`)
    
    // Create a proper axios instance with correct configuration
    this.axiosInstance = axios.create({
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
        // API key will be added by the proxy or sent directly depending on implementation
        ...(useProxy ? {} : { 'apiKey': this.apiKey })
      }
    })
    
    // Rate limit tracking
    this.rateLimits = {
      total: 50, // Default NVD API rate limit: 50 requests per 30 seconds in a rolling window
      remaining: 50,
      requestTimestamps: [], // Track timestamps of recent requests to enforce rate limits
      windowSeconds: 30,
      resetTime: null
    }
    
    // Add request retry interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => {
        // Update rate limit info from headers if available
        this.updateRateLimitsFromHeaders(response.headers)
        return response
      },
      async (error) => {
        const { config } = error
        
        // Update rate limit info from error headers if available
        if (error.response?.headers) {
          this.updateRateLimitsFromHeaders(error.response.headers)
        }
        
        // If retries aren't configured or we've reached max retries, throw the error
        if (!config || !config.retry || config.__retryCount >= config.retry) {
          return Promise.reject(error)
        }
        
        // If we hit a rate limit, wait according to retry-after or use exponential backoff
        if (error.response?.status === 429) {
          const retryAfter = error.response.headers['retry-after']
          const waitTime = retryAfter ? parseInt(retryAfter, 10) * 1000 : 30000 // Default to 30 seconds
          
          console.log(`Rate limit hit, waiting ${waitTime/1000} seconds before retry...`)
          await new Promise(resolve => setTimeout(resolve, waitTime))
          
          // Reset rate limit tracking after waiting
          this.rateLimits.requestTimestamps = []
          this.rateLimits.remaining = this.rateLimits.total
        } else {
          // Count this attempt
          config.__retryCount = config.__retryCount || 0
          config.__retryCount++
          
          // Calculate backoff time
          const backoff = Math.pow(2, config.__retryCount) * 1000
          
          console.log(`NVD API request failed, retrying in ${backoff}ms (Attempt ${config.__retryCount}/${config.retry})`)
          
          // Wait for the backoff period
          await new Promise(resolve => setTimeout(resolve, backoff))
        }
        
        // Retry the request
        return this.axiosInstance(config)
      }
    )
    
    // Add error handling for missing API key
    if (!this.apiKey && !useProxy) {
      console.error('NVD API key is missing. Set VITE_NIST_API_KEY in your .env file')
    }
  }
  
  /**
   * Update rate limit information from response headers
   * @param {Object} headers - Response headers
   */
  updateRateLimitsFromHeaders(headers) {
    // Check if rate limit headers exist
    const rateLimitTotal = headers['x-ratelimit-limit'] || headers['x-rate-limit-limit']
    const rateLimitRemaining = headers['x-ratelimit-remaining'] || headers['x-rate-limit-remaining']
    const rateLimitReset = headers['x-ratelimit-reset'] || headers['x-rate-limit-reset']
    
    if (rateLimitTotal) {
      this.rateLimits.total = parseInt(rateLimitTotal, 10)
    }
    
    if (rateLimitRemaining) {
      this.rateLimits.remaining = parseInt(rateLimitRemaining, 10)
    }
    
    if (rateLimitReset) {
      // Convert to Date object if it's a timestamp
      if (!isNaN(rateLimitReset)) {
        this.rateLimits.resetTime = new Date(rateLimitReset * 1000)
      } else {
        this.rateLimits.resetTime = rateLimitReset
      }
    }
  }
  
  /**
   * Track an API request and enforce rate limits
   * @returns {Promise<void>} Resolves when it's safe to make a request
   */
  async trackAndEnforceRateLimit() {
    const now = Date.now()
    const windowMs = this.rateLimits.windowSeconds * 1000
    
    // Remove timestamps older than the rate limit window
    this.rateLimits.requestTimestamps = this.rateLimits.requestTimestamps.filter(
      timestamp => now - timestamp < windowMs
    )
    
    // Check if we're at the rate limit
    if (this.rateLimits.requestTimestamps.length >= this.rateLimits.total) {
      // Calculate time until oldest request drops out of window
      const oldestTimestamp = this.rateLimits.requestTimestamps[0]
      const timeToWait = oldestTimestamp + windowMs - now
      
      if (timeToWait > 0) {
        console.log(`Rate limit reached. Waiting ${timeToWait}ms before next request...`)
        await new Promise(resolve => setTimeout(resolve, timeToWait))
      }
      
      // Remove timestamps older than the rate limit window after waiting
      const newNow = Date.now()
      this.rateLimits.requestTimestamps = this.rateLimits.requestTimestamps.filter(
        timestamp => newNow - timestamp < windowMs
      )
    }
    
    // Add current timestamp to the list
    this.rateLimits.requestTimestamps.push(Date.now())
  }
  
  /**
   * Check if the NVD API is available and the API key is valid
   * @returns {Promise<boolean>} - True if API is available and key is valid
   */
  async checkApiAvailability() {
    try {
      // Test with a well-known CVE
      const testCveId = 'CVE-2021-44228'
      console.log(`Testing NVD API availability with ${testCveId}...`)
      
      const response = await this.axiosInstance.get(`${this.apiBaseUrl}`, {
        params: { cveId: testCveId },
        retry: 1
      })
      
      // Check response headers for rate limit information
      this.checkRateLimitHeaders(response.headers)
      
      const isAvailable = response.status === 200 && 
                          response.data?.vulnerabilities?.length > 0
      
      if (isAvailable) {
        console.log('✅ NVD API is available and the API key is valid.')
      } else {
        console.error('❌ NVD API response was successful but no data was returned.')
      }
      
      return isAvailable
    } catch (error) {
      if (error.response?.status === 403) {
        console.error('❌ NVD API key is invalid or missing. Check your VITE_NIST_API_KEY in .env file.')
      } else if (error.response?.status === 429) {
        console.error('❌ NVD API rate limit reached. Try again later.')
        // Check response headers for rate limit information
        if (error.response?.headers) {
          this.checkRateLimitHeaders(error.response.headers)
        }
      } else {
        console.error('❌ NVD API is not available:', error.message)
      }
      return false
    }
  }
  
  /**
   * Check response headers for rate limit information
   * @param {Object} headers - Response headers
   */
  checkRateLimitHeaders(headers) {
    // Common rate limit headers to check
    const rateLimitTotal = headers['x-ratelimit-limit'] || headers['x-rate-limit-limit']
    const rateLimitRemaining = headers['x-ratelimit-remaining'] || headers['x-rate-limit-remaining']
    const rateLimitReset = headers['x-ratelimit-reset'] || headers['x-rate-limit-reset']
    
    if (rateLimitTotal && rateLimitRemaining) {
      console.log(`📊 Rate limit: ${rateLimitRemaining}/${rateLimitTotal} requests remaining`)
      
      // Calculate percentage of rate limit used
      const percentUsed = ((rateLimitTotal - rateLimitRemaining) / rateLimitTotal) * 100
      
      // Alert if we're close to the limit
      if (percentUsed > 80) {
        console.warn(`⚠️ Warning: ${percentUsed.toFixed(1)}% of rate limit used!`)
      }
      
      if (rateLimitReset) {
        // Convert to human-readable time if it's a timestamp
        let resetTime = rateLimitReset
        if (!isNaN(rateLimitReset)) {
          resetTime = new Date(rateLimitReset * 1000).toLocaleTimeString()
        }
        console.log(`🕒 Rate limit resets at: ${resetTime}`)
      }
    }
  }

  /**
   * Fetch CVE data from NVD API
   * @param {string} cveId - CVE ID to fetch
   * @returns {Promise<Object>} - CVE data
   */
  async fetchCVEData(cveId) {
    try {
      // If you have rate limiting code, keep it
      if (this.trackAndEnforceRateLimit) {
        await this.trackAndEnforceRateLimit();
      }
      
      const response = await this.axiosInstance.get(`${this.apiBaseUrl}`, {
        params: {
          cveId
        },
        // Configure retry settings
        retry: 3 // Maximum 3 retry attempts
      })
      
      // If you have rate limit header checking, keep it
      if (this.checkRateLimitHeaders) {
        this.checkRateLimitHeaders(response.headers);
      }
      
      return response.data.vulnerabilities?.[0]?.cve || null
    } catch (error) {
      // Check for proxy-specific errors
      if (error.message?.includes('Network Error') || error.code === 'ERR_NETWORK') {
        console.error(`Network error while connecting to NVD API. This may be a proxy issue. Check your server configuration.`);
      } else if (error.response?.status === 404 && this.apiBaseUrl.startsWith('/api/proxy')) {
        console.error(`Proxy endpoint not found. Ensure your proxy is properly configured in your server.`);
      } else if (error.response?.status === 403) {
        console.error(`Access denied. API key may be invalid or missing. Check your API key configuration.`);
      }
      // Check for rate limiting errors
      else if (error.response?.status === 429) {
        console.warn(`Rate limit exceeded while fetching ${cveId}`);
        
        // Check response headers for rate limit information
        if (error.response?.headers && this.checkRateLimitHeaders) {
          this.checkRateLimitHeaders(error.response.headers);
          
          // Get retry-after header if available
          const retryAfter = error.response.headers['retry-after'];
          if (retryAfter) {
            const waitTime = parseInt(retryAfter, 10) * 1000 || 5000;
            console.log(`Waiting ${waitTime}ms as specified by API before retrying...`);
            await new Promise(resolve => setTimeout(resolve, waitTime));
            
            // Reset rate limit tracking if available
            if (this.rateLimits) {
              this.rateLimits.requestTimestamps = [];
            }
            
            // Try again after waiting
            return this.fetchCVEData(cveId);
          }
        }
      } else {
        console.error(`Error fetching CVE ${cveId} from NVD:`, error.message);
      }
      
      throw error;
    }
  }

  /**
   * Extract severity information from CVE data
   * @param {Object} cveData - CVE data from NVD API
   * @returns {Object} - Severity information with level and score
   */
  extractSeverity(cveData) {
    let severity = {
      level: SEVERITY_LEVELS.NONE,
      score: 0
    }

    try {
      // First try CVSS v3.1 (preferred)
      if (cveData.metrics?.cvssMetricV31) {
        const cvssV31 = cveData.metrics.cvssMetricV31[0]
        severity.score = cvssV31.cvssData?.baseScore || 0
        severity.level = cvssV31.cvssData?.baseSeverity || SEVERITY_LEVELS.NONE
      }
      // If no CVSS v3.1, try CVSS v3.0
      else if (cveData.metrics?.cvssMetricV30) {
        const cvssV30 = cveData.metrics.cvssMetricV30[0]
        severity.score = cvssV30.cvssData?.baseScore || 0
        severity.level = cvssV30.cvssData?.baseSeverity || SEVERITY_LEVELS.NONE
      }
      // If no CVSS v3.x, try CVSS v2.0
      else if (cveData.metrics?.cvssMetricV2) {
        const cvssV2 = cveData.metrics.cvssMetricV2[0]
        severity.score = cvssV2.cvssData?.baseScore || 0
        
        // Convert CVSS v2 score to severity level
        if (severity.score >= 9.0) severity.level = SEVERITY_LEVELS.CRITICAL
        else if (severity.score >= 7.0) severity.level = SEVERITY_LEVELS.HIGH
        else if (severity.score >= 4.0) severity.level = SEVERITY_LEVELS.MEDIUM
        else if (severity.score > 0) severity.level = SEVERITY_LEVELS.LOW
        else severity.level = SEVERITY_LEVELS.NONE
      }
    } catch (error) {
      console.error('Error extracting severity from CVE data:', error.message)
    }

    return severity
  }
  
  /**
   * Batch fetch CVE data for multiple CVE IDs
   * @param {Array<string>} cveIds - Array of CVE IDs
   * @param {Function} progressCallback - Optional callback to report progress
   * @returns {Promise<Object>} - Object with CVE IDs as keys and severity data as values
   */
  async batchFetchCVESeverities(cveIds, progressCallback) {
    console.log(`Starting batch processing of ${cveIds.length} CVEs from NVD API...`)
    
    // Check API availability before proceeding
    const isApiAvailable = await this.checkApiAvailability()
    if (!isApiAvailable) {
      throw new Error('NVD API is not available. Please check your API key and try again later.')
    }
    
    // Using our built-in rate limiting
    const results = {}
    const maxRetries = 3
    
    let processedCount = 0
    let successCount = 0
    let failureCount = 0
    
    // Process CVEs one at a time with rate limiting handled by trackAndEnforceRateLimit
    for (let i = 0; i < cveIds.length; i++) {
      const cveId = cveIds[i]
      console.log(`Processing CVE ${i + 1}/${cveIds.length}: ${cveId}`)
      
      let retryCount = 0
      let success = false
      
      while (!success && retryCount < maxRetries) {
        try {
          // fetchCVEData already has rate limiting built in
          const cveData = await this.fetchCVEData(cveId)
          if (cveData) {
            results[cveId] = this.extractSeverity(cveData)
            console.log(`Successfully processed ${cveId}: ${results[cveId].level} (${results[cveId].score})`)
            successCount++
          } else {
            console.warn(`No data returned for ${cveId}, setting default severity`)
            results[cveId] = { level: SEVERITY_LEVELS.NONE, score: 0 }
            failureCount++
          }
          success = true
        } catch (error) {
          retryCount++
          
          // Handle rate limiting errors specially
          if (error.response?.status === 429) {
            console.warn(`Rate limit hit for ${cveId}, waiting longer before retry...`)
            // Wait longer if we hit rate limit - 10 seconds + exponential backoff
            await new Promise(resolve => setTimeout(resolve, 10000 + Math.pow(2, retryCount) * 1000))
            
            // Reset rate limit tracking
            this.rateLimits.requestTimestamps = []
          } else if (retryCount < maxRetries) {
            console.log(`Error processing ${cveId}, retry attempt ${retryCount}/${maxRetries}`)
            // Exponential backoff delay between retries
            await new Promise(resolve => setTimeout(resolve, Math.pow(2, retryCount) * 1000))
          } else {
            console.error(`Failed to process ${cveId} after ${maxRetries} attempts: ${error.message}`)
            // Set default values for failures
            results[cveId] = { level: SEVERITY_LEVELS.NONE, score: 0 }
            failureCount++
          }
        } finally {
          // Report progress for this CVE regardless of success or failure
          processedCount++
          if (progressCallback && typeof progressCallback === 'function') {
            progressCallback(cveId)
          }
        }
      }
      
      // Log progress every 10 CVEs
      if ((i + 1) % 10 === 0 || i === cveIds.length - 1) {
        console.log(`Progress: ${i + 1}/${cveIds.length} CVEs processed (${successCount} successful, ${failureCount} failed)`)
      }
    }
    
    console.log(`Batch processing complete: ${processedCount} total, ${successCount} successful, ${failureCount} failed`)
    return results
  }
}

export default new NVDService() 