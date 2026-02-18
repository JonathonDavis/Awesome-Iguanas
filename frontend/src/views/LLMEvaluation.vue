<template>
  <div class="llm-evaluation-container">
    <div class="section-header">
      <h1>LLM Vulnerability Evaluation</h1>
      <p class="subtitle">AI-powered vulnerability findings analysis</p>
    </div>

    <!-- Filter Section -->
    <div class="filter-section">
      <div class="search-container">
        <div class="filter-group">
          <label for="headline-filter">Headline/Title:</label>
          <input 
            id="headline-filter"
            type="text" 
            v-model="headlineFilter" 
            placeholder="Search by headline..." 
            @input="applyFilters"
            class="search-input"
          />
        </div>
        <div class="filter-group">
          <label for="github-filter">GitHub Repository:</label>
          <input 
            id="github-filter"
            type="text" 
            v-model="githubFilter" 
            placeholder="Filter by GitHub Repository ID..." 
            @input="applyFilters"
            class="search-input"
          />
        </div>
        <div class="filter-group">
          <label for="classification-filter">Classification:</label>
          <select 
            id="classification-filter"
            v-model="classificationFilter" 
            @change="applyFilters"
            class="classification-select"
          >
            <option value="">All Classifications</option>
            <option value="Very Promising">Very Promising</option>
            <option value="Slightly Promising">Slightly Promising</option>
            <option value="Not Promising">Not Promising</option>
            <option value="N/A">N/A</option>
          </select>
        </div>
        <button @click="clearFilters" class="clear-button">
          <i class="fas fa-times"></i> Clear
        </button>
      </div>
    </div>

    <!-- Findings Display Section -->
    <div class="card">
      <h2 class="heading-secondary">Vulnerability Findings</h2>
      <div v-if="loading" class="loading-state">
        <i class="fas fa-spinner fa-spin"></i>
        <p>Loading vulnerability findings...</p>
      </div>
      <div v-else-if="error" class="error-message">
        <i class="fas fa-exclamation-circle"></i> Error: {{ error }}
      </div>
      <div v-else-if="!findings || findings.length === 0" class="empty-state">
        <i class="fas fa-shield-alt"></i>
        <p>No vulnerability findings available</p>
      </div>
      <div v-else class="findings-grid">
        <div v-for="finding in findings" :key="finding.id" class="finding-card">
          <div class="finding-card-header">
            <h3>{{ finding.headline || finding.properties?.headline || 'Unnamed Finding' }}</h3>
            <span class="confidence-badge" :class="getClassificationClass(finding.classification || finding.properties?.classification)">
              {{ finding.classification || finding.properties?.classification || 'UNKNOWN' }}
            </span>
          </div>
          <p class="summary">{{ finding.analysis || finding.properties?.analysis || 'No analysis available' }}</p>
          <div class="metadata">
            <span class="metadata-item" v-if="finding.id || finding.properties?.id">
              <i class="fab fa-github"></i> {{ extractGithubId(finding.id || finding.properties?.id) }}
            </span>
            <span class="metadata-item" v-if="finding.timestamp || finding.properties?.timestamp">
              <i class="fas fa-calendar-alt"></i> {{ formatTimestamp(finding.timestamp || finding.properties?.timestamp) }}
            </span>
            <span class="metadata-item" v-if="finding.source || finding.properties?.source">
              <i class="fas fa-code-branch"></i> {{ finding.source || finding.properties?.source }}
            </span>
          </div>
          <button class="view-details-btn" @click="showFindingDetails(finding)">
            <i class="fas fa-info-circle"></i> View Details
          </button>
        </div>
      </div>
    </div>

    <!-- Finding Details Modal -->
    <div v-if="selectedFinding" class="modal-overlay" @click.self="selectedFinding = null">
      <div class="modal-content">
        <div class="modal-header">
          <h2>{{ selectedFinding.headline || selectedFinding.properties?.headline || 'Unnamed Finding' }}</h2>
          <button class="close-button" @click="selectedFinding = null">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="modal-body">
          <div class="detail-section">
            <h3><i class="fas fa-info-circle"></i> Overview</h3>
            <div class="detail-item">
              <strong>Analysis:</strong>
              <p>{{ selectedFinding.analysis || selectedFinding.properties?.analysis || 'No analysis available' }}</p>
            </div>
            <div class="detail-item">
              <strong>Classification:</strong>
              <span class="confidence-badge large" :class="getClassificationClass(selectedFinding.classification || selectedFinding.properties?.classification)">
                {{ selectedFinding.classification || selectedFinding.properties?.classification || 'UNKNOWN' }}
              </span>
            </div>
          </div>
          
          <div class="detail-section" v-if="selectedFinding.cve_reference || selectedFinding.properties?.cve_reference">
            <h3><i class="fas fa-bug"></i> Vulnerability Reference</h3>
            <div class="detail-item">
              <strong>CVE/CWE Reference:</strong>
              <p>{{ selectedFinding.cve_reference || selectedFinding.properties?.cve_reference }}</p>
            </div>
          </div>
          
          <div class="detail-section" v-if="selectedFinding.key_filenames || selectedFinding.properties?.key_filenames || selectedFinding.key_functions || selectedFinding.properties?.key_functions">
            <h3><i class="fas fa-code"></i> Code Information</h3>
            <div class="detail-item" v-if="selectedFinding.key_filenames || selectedFinding.properties?.key_filenames">
              <strong>Key Files:</strong>
              <p>{{ selectedFinding.key_filenames || selectedFinding.properties?.key_filenames }}</p>
            </div>
            <div class="detail-item" v-if="selectedFinding.key_functions || selectedFinding.properties?.key_functions">
              <strong>Key Functions:</strong>
              <p>{{ selectedFinding.key_functions || selectedFinding.properties?.key_functions }}</p>
            </div>
          </div>
          
          <div class="detail-section" v-if="selectedFinding.id || selectedFinding.properties?.id">
            <h3><i class="fab fa-github"></i> Repository Information</h3>
            <div class="detail-item">
              <strong>GitHub ID:</strong>
              <p>{{ extractGithubId(selectedFinding.id || selectedFinding.properties?.id) }}</p>
            </div>
            <div class="detail-item" v-if="selectedFinding.source || selectedFinding.properties?.source">
              <strong>Source:</strong>
              <p>{{ selectedFinding.source || selectedFinding.properties?.source }}</p>
            </div>
          </div>
        </div>
        <div class="modal-footer">
          <button class="close-btn" @click="selectedFinding = null">Close</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import neo4jService from '../services/neo4j/neo4jService'

export default {
  name: 'LLMEvaluation',
  setup() {
    const findings = ref([])
    const allFindings = ref([])
    const selectedFinding = ref(null)
    const loading = ref(true)
    const error = ref(null)
    const githubFilter = ref('')
    const classificationFilter = ref('')
    const headlineFilter = ref('')

    const fetchVulnerabilityFindings = async () => {
      loading.value = true
      error.value = null
      
      try {
        const session = neo4jService.driver.session()
        
        const result = await session.run(`
          MATCH (n:AIVulnerabilityFinding)
          RETURN n, properties(n) as props, labels(n) as labels
        `)
        
        console.log('Neo4j query result:', result)
        console.log('Records count:', result.records.length)
        
        if (result.records.length > 0) {
          console.log('Sample record:', result.records[0].get('n'))
          console.log('Sample properties:', result.records[0].get('props'))
          console.log('Sample labels:', result.records[0].get('labels'))
        }
        
        allFindings.value = result.records.map(record => {
          const finding = record.get('n')
          const props = record.get('props')
          const processedFinding = {
            id: finding.identity.toString(),
            labels: finding.labels || record.get('labels'),
            properties: finding.properties || props,
            ...finding.properties,
            ...props
          }
          console.log('Processed finding:', processedFinding)
          return processedFinding
        })
        
        console.log('All findings:', allFindings.value)
        
        findings.value = [...allFindings.value]
        loading.value = false
        
        await session.close()
      } catch (err) {
        console.error('Error fetching vulnerability findings:', err)
        error.value = err.message || 'Failed to fetch vulnerability findings'
        loading.value = false
      }
    }

    const applyFilters = () => {
      console.log('Applying filters - Headline:', headlineFilter.value, 'GitHub:', githubFilter.value, 'Classification:', classificationFilter.value)
      
      findings.value = allFindings.value.filter(finding => {
        // Filter by headline/title
        const headline = (finding.headline || finding.properties?.headline || '').toLowerCase()
        const matchesHeadline = !headlineFilter.value.trim() || 
                               headline.includes(headlineFilter.value.toLowerCase().trim())
                               
        // Filter by GitHub ID
        const githubId = (finding.id || finding.properties?.id || '').toLowerCase()
        const matchesGithub = !githubFilter.value.trim() || 
                             githubId.includes(githubFilter.value.toLowerCase().trim())
        
        // Filter by classification - exact match for the classification
        const classification = (finding.classification || finding.properties?.classification || '')
        
        // Special handling for N/A option
        let matchesClassification = false;
        if (classificationFilter.value === 'N/A') {
          // Match if classification is empty OR explicitly "N/A"
          matchesClassification = !classification || classification === 'N/A';
        } else {
          matchesClassification = !classificationFilter.value || 
                                 classification === classificationFilter.value;
        }
        
        // All filters must match
        const matches = matchesHeadline && matchesGithub && matchesClassification
        console.log(`Finding ${finding.id}: Headline match: ${matchesHeadline}, GitHub match: ${matchesGithub}, Classification match: ${matchesClassification}`)
        
        return matches
      })
      
      console.log('Filtered findings:', findings.value.length)
    }
    
    const clearFilters = () => {
      headlineFilter.value = ''
      githubFilter.value = ''
      classificationFilter.value = ''
      findings.value = [...allFindings.value]
      console.log('Filters cleared, showing all findings:', findings.value.length)
    }
    
    const showFindingDetails = (finding) => {
      selectedFinding.value = finding
    }
    
    const getConfidenceClass = (confidence) => {
      console.log('Confidence value:', confidence)
      if (!confidence) return 'unknown'
      
      const confidenceLevel = confidence.toLowerCase()
      if (confidenceLevel.includes('high')) return 'high'
      if (confidenceLevel.includes('medium')) return 'medium'
      if (confidenceLevel.includes('low')) return 'low'
      return 'unknown'
    }
    
    const getClassificationClass = (classification) => {
      console.log('Classification value:', classification)
      if (!classification) return 'unknown'
      
      const classificationLower = classification.toLowerCase()
      if (classificationLower.includes('very promising') || classificationLower.includes('high')) return 'high'
      if (classificationLower.includes('promising') || classificationLower.includes('medium')) return 'medium'
      if (classificationLower.includes('unlikely') || classificationLower.includes('low')) return 'low'
      return 'unknown'
    }
    
    const formatDate = (dateString) => {
      if (!dateString) return 'Unknown date'
      
      try {
        const date = new Date(dateString)
        return date.toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric'
        })
      } catch (err) {
        return dateString
      }
    }
    
    const extractGithubId = (fullId) => {
      if (!fullId) return 'Unknown repository'
      
      try {
        try {
          const url = new URL(fullId.replace(/https:__/g, 'https://'));
          if (url.hostname === 'github.com' || url.hostname.endsWith('.github.com')) {
            return url.pathname.replace(/^\/+|\/+$/g, ''); // Clean up leading/trailing slashes
          }
        } catch (err) {
          // Invalid URL, fallback to returning fullId
          return fullId;
        return fullId
      } catch (err) {
        return fullId
      }
    }
    
    const formatTimestamp = (timestamp) => {
      if (!timestamp) return 'Unknown date'
      
      try {
        const ts = Number(timestamp)
        if (!isNaN(ts)) {
          const date = new Date(ts * 1000)
          return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
          })
        }
        return timestamp
      } catch (err) {
        return timestamp
      }
    }
    
    onMounted(() => {
      fetchVulnerabilityFindings()
    })
    
    return {
      findings,
      selectedFinding,
      loading,
      error,
      githubFilter,
      classificationFilter,
      headlineFilter,
      showFindingDetails,
      applyFilters,
      clearFilters,
      getConfidenceClass,
      getClassificationClass,
      formatDate,
      extractGithubId,
      formatTimestamp
    }
  }
}
</script>

<style scoped>
.llm-evaluation-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.section-header {
  margin-bottom: 30px;
  text-align: center;
}

.section-header h1 {
  font-size: 2.5rem;
  color: var(--secondary-color);
  margin-bottom: 10px;
}

.subtitle {
  font-size: 1.2rem;
  color: var(--light-text);
}

.card {
  background-color: var(--card-background);
  border-radius: 8px;
  box-shadow: 0 4px 12px var(--shadow-color);
  margin-bottom: 30px;
  padding: 25px;
}

.heading-secondary {
  font-size: 1.8rem;
  color: var(--secondary-color);
  margin-bottom: 20px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border-color);
}

.filter-section {
  margin-bottom: 25px;
}

.search-container {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  align-items: flex-end;
  gap: 15px;
  max-width: 1000px;
  margin: 0 auto;
}

.filter-group {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 200px;
}

.filter-group label {
  font-size: 0.9rem;
  margin-bottom: 5px;
  color: var(--text-color);
  font-weight: 500;
}

.search-input,
.classification-select {
  padding: 12px 15px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 1rem;
  transition: border-color 0.3s;
  background-color: var(--card-background);
  color: var(--text-color);
}

.search-input:focus,
.classification-select:focus {
  border-color: var(--primary-color);
  outline: none;
}

.classification-select {
  background-color: var(--card-background);
  appearance: none;
  background-image: url("data:image/svg+xml;charset=UTF-8,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3e%3cpolyline points='6 9 12 15 18 9'%3e%3c/polyline%3e%3c/svg%3e");
  background-repeat: no-repeat;
  background-position: right 1rem center;
  background-size: 1em;
  cursor: pointer;
}

.filter-button, .clear-button {
  padding: 12px 20px;
  border: none;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.3s;
}

.filter-button {
  background-color: var(--primary-color);
  color: white;
}

.filter-button:hover {
  background-color: var(--primary-dark);
}

.clear-button {
  background-color: var(--background-dark);
  color: var(--secondary-color);
}

.clear-button:hover {
  background-color: var(--border-color);
}

.loading-state, .empty-state {
  text-align: center;
  padding: 40px 0;
  color: var(--light-text);
}

.loading-state i, .empty-state i {
  font-size: 3rem;
  margin-bottom: 15px;
  display: block;
  color: var(--secondary-light);
}

.error-message {
  background-color: #fdeded;
  color: var(--error-color);
  padding: 15px;
  border-radius: 6px;
  margin-bottom: 20px;
}

.findings-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
}

.finding-card {
  background-color: var(--background-color);
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 2px 8px var(--shadow-color);
  transition: transform 0.2s, box-shadow 0.2s;
}

.finding-card:hover {
  transform: translateY(-3px);
  box-shadow: 0 4px 12px var(--shadow-color);
}

.finding-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.finding-card-header h3 {
  font-size: 1.2rem;
  margin: 0;
  color: var(--text-color);
}

.confidence-badge {
  padding: 5px 10px;
  border-radius: 50px;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
}

.confidence-badge.high {
  background-color: #ffebee;
  color: var(--error-color);
}

.confidence-badge.medium {
  background-color: #fff8e1;
  color: var(--warning-color);
}

.confidence-badge.low {
  background-color: #e8f5e9;
  color: var(--success-color);
}

.confidence-badge.unknown {
  background-color: var(--background-dark);
  color: var(--light-text);
}

.confidence-badge.large {
  font-size: 1rem;
  padding: 8px 15px;
}

.summary {
  font-size: 0.95rem;
  color: var(--text-color);
  margin-bottom: 15px;
  line-height: 1.5;
  max-height: 4.5rem;
  overflow: hidden;
  display: -webkit-box;
  -webkit-line-clamp: 3;
  -webkit-box-orient: vertical;
}

.metadata {
  display: flex;
  gap: 15px;
  margin-bottom: 15px;
  flex-wrap: wrap;
}

.metadata-item {
  font-size: 0.85rem;
  color: var(--light-text);
  display: flex;
  align-items: center;
  max-width: 100%;
  word-break: break-word;
  overflow-wrap: break-word;
}

.metadata-item i {
  margin-right: 5px;
  flex-shrink: 0;
  color: var(--secondary-color);
}

.view-details-btn {
  width: 100%;
  padding: 10px;
  background-color: var(--primary-color);
  color: white;
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.3s;
}

.view-details-btn:hover {
  background-color: var(--primary-dark);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.5);
  display: flex;
  justify-content: center;
  align-items: center;
  z-index: 1000;
}

.modal-content {
  background-color: var(--card-background);
  border-radius: 8px;
  width: 90%;
  max-width: 800px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 4px 20px var(--shadow-color);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid var(--border-color);
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  color: var(--secondary-color);
}

.close-button {
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: var(--light-text);
}

.modal-body {
  padding: 20px;
}

.detail-section {
  margin-bottom: 25px;
}

.detail-section h3 {
  font-size: 1.2rem;
  color: var(--text-color);
  margin-bottom: 15px;
  display: flex;
  align-items: center;
}

.detail-section h3 i {
  margin-right: 10px;
  color: var(--primary-color);
}

.detail-item {
  margin-bottom: 15px;
}

.detail-item strong {
  display: block;
  margin-bottom: 5px;
  color: var(--light-text);
}

.detail-item p {
  margin: 0;
  line-height: 1.6;
  color: var(--text-color);
}

.detail-item pre {
  background-color: var(--background-color);
  padding: 15px;
  border-radius: 6px;
  overflow-x: auto;
  font-size: 0.9rem;
  margin: 0;
  color: var(--text-color);
}

.modal-footer {
  padding: 15px 20px;
  border-top: 1px solid var(--border-color);
  text-align: right;
}

.close-btn {
  padding: 10px 20px;
  background-color: var(--background-dark);
  color: var(--secondary-color);
  border: none;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 0.3s;
}

.close-btn:hover {
  background-color: var(--border-color);
}

@media (max-width: 768px) {
  .findings-grid {
    grid-template-columns: 1fr;
  }
  
  .search-container {
    flex-direction: column;
  }
  
  .filter-group,
  .search-input, 
  .classification-select,
  .filter-button, 
  .clear-button {
    width: 100%;
  }
}
</style>
